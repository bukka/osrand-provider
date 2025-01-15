#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define PROVIDER_NAME "OSRand"
#define PROVIDER_VERSION "0.1"

#define RET_OSSL_OK 1
#define RET_OSSL_ERR 0
#define RET_OSSL_BAD -1

#define OSRAND_E_DEVICE_OPEN_FAIL 1
#define OSRAND_E_DEVICE_READ_FAIL 2
#define OSRAND_E_GETRANDOM_FAIL 3

static OSSL_FUNC_core_get_params_fn *core_get_params = NULL;
static OSSL_FUNC_core_new_error_fn *core_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn *core_vset_error = NULL;

/* Modes for selecting the source */
typedef enum {
    OSRAND_MODE_GETRANDOM,
    OSRAND_MODE_DEVLRNG,
    OSRAND_MODE_DEVRANDOM
} OSRAND_MODE;

#define OSRAND_PARAM_MODE "osrand-mode"

#define OSRAND_MODE_GETRANDOM_NAME "getrandom"
#define OSRAND_MODE_DEVLRNG_NAME "devlrng"
#define OSRAND_MODE_DEVRANDOM_NAME "devrandom"

typedef struct {
    int fd;
    dev_t dev;
    ino_t ino;
    mode_t mode;
    dev_t rdev;
} OSRAND_RANDOM_DEVICE;

/* Provider context structure */
typedef struct {
    /* Current mode */
    OSRAND_MODE mode;
    /* Provider handles */
    const OSSL_CORE_HANDLE *handle;
} OSRAND_PROV_CTX;

/* RAND context structure */
typedef struct {
    /* Provider context */
    OSRAND_PROV_CTX *provctx;
    /* Random device if device used */
    OSRAND_RANDOM_DEVICE rd;
} OSRAND_RAND_CTX;

static void osrand_raise(OSRAND_PROV_CTX *ctx, const char *file, int line,
                         const char *func, int errnum, const char *fmt, ...)
{
    va_list args;

    if (!core_new_error || !core_vset_error) {
        return;
    }

    va_start(args, fmt);
    core_new_error(ctx->handle);
    core_set_error_debug(ctx->handle, file, line, func);
    core_vset_error(ctx->handle, errnum, fmt, args);
    va_end(args);
}

#define OSRAND_raise(ctx, errnum, format, ...) \
    osrand_raise((ctx), OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, (errnum), \
                 format, ##__VA_ARGS__)

/* Check whether random device fd is still open and device is valid */
static int osrand_check_random_device(OSRAND_RANDOM_DEVICE *rd)
{
    struct stat st;

    return rd->fd != -1 && fstat(rd->fd, &st) != -1 && rd->dev == st.st_dev
           && rd->ino == st.st_ino
           && ((rd->mode ^ st.st_mode) & ~(S_IRWXU | S_IRWXG | S_IRWXO)) == 0
           && rd->rdev == st.st_rdev;
}

/* Open a random device if required and return its file descriptor */
static int osrand_get_random_device(OSRAND_RANDOM_DEVICE *rd,
                                    const char *device_path)
{
    struct stat st;

    /* reuse existing file descriptor if it is (still) valid */
    if (osrand_check_random_device(rd)) return rd->fd;

    /* open the random device ... */
    if ((rd->fd = open(device_path, O_RDONLY)) == -1) return rd->fd;

    /* ... and cache its relevant stat(2) data */
    if (fstat(rd->fd, &st) != -1) {
        rd->dev = st.st_dev;
        rd->ino = st.st_ino;
        rd->mode = st.st_mode;
        rd->rdev = st.st_rdev;
    } else {
        close(rd->fd);
        rd->fd = -1;
    }

    return rd->fd;
}

/* Close a random device making sure it is a random device */
static void osrand_close_random_device(OSRAND_RANDOM_DEVICE *rd)
{
    if (osrand_check_random_device(rd)) close(rd->fd);
    rd->fd = -1;
}

/* Generate random bytes using a device file */
static int osrand_generate_from_device(OSRAND_RAND_CTX *ctx,
                                       const char *device_path,
                                       unsigned char *buf, size_t buflen)
{
    int fd = osrand_get_random_device(&ctx->rd, device_path);
    if (fd == -1) {
        OSRAND_raise(ctx->provctx, OSRAND_E_DEVICE_OPEN_FAIL,
                     "Failed to open device %s", device_path);
        return RET_OSSL_ERR; /* Failed to retrieving the device */
    }

    ssize_t total_read = 0;
    while (total_read < (ssize_t)buflen) {
        ssize_t ret = read(fd, buf + total_read, buflen - total_read);
        if (ret <= 0) {
            if (ret == -1 && errno == EINTR) {
                continue; /* Retry on interrupt */
            }
            OSRAND_raise(ctx->provctx, OSRAND_E_DEVICE_READ_FAIL,
                         "Failed to to read from device %s", device_path);
            return RET_OSSL_ERR; /* Read error */
        }
        total_read += ret;
    }

    return RET_OSSL_OK;
}

/* Generate random bytes using getrandom */
static int osrand_generate_using_getrandom(OSRAND_RAND_CTX *ctx,
                                           unsigned char *buf, size_t buflen)
{
    ssize_t ret = getrandom(buf, buflen, 0);
    if (ret == -1) {
        OSRAND_raise(ctx->provctx, OSRAND_E_DEVICE_READ_FAIL,
                     "Failed to get %zu bytes using getrandom", buflen);
        return 0;
    }

    return ((size_t)ret != buflen) ? 0 : 1;
}

/* RAND generate function */
static int osrand_generate(void *vctx, unsigned char *buf, size_t buflen,
                           unsigned int strength, int prediction_resistance)
{
    OSRAND_RAND_CTX *ctx = (OSRAND_RAND_CTX *)vctx;
    (void)strength;
    (void)prediction_resistance;

    switch (ctx->provctx->mode) {
    case OSRAND_MODE_GETRANDOM:
        return osrand_generate_using_getrandom(ctx, buf, buflen);
    case OSRAND_MODE_DEVLRNG:
        return osrand_generate_from_device(ctx, "/dev/lrng", buf, buflen);
    case OSRAND_MODE_DEVRANDOM:
        return osrand_generate_from_device(ctx, "/dev/random", buf, buflen);
    default:
        return RET_OSSL_ERR; /* Unknown mode */
    }
}

/* RAND reseed function */
static int osrand_reseed(void *pctx, int prediction_resistance,
                         const unsigned char *entropy, size_t ent_len,
                         const unsigned char *adin, size_t adin_len)
{
    return RET_OSSL_OK;
}

/* RAND new context */
static void *osrand_newctx(void *provctx)
{
    OSRAND_RAND_CTX *ctx = OPENSSL_malloc(sizeof(OSRAND_RAND_CTX));
    if (ctx == NULL) return NULL;
    ctx->rd.fd = -1;
    ctx->provctx = provctx;
    return ctx;
}

/* RAND free context */
static void osrand_freectx(void *vctx)
{
    OSRAND_RAND_CTX *ctx = (OSRAND_RAND_CTX *)vctx;
    osrand_close_random_device(&ctx->rd);
    OPENSSL_free(ctx);
}

static int osrand_instantiate(void *vctx, unsigned int strength,
                              int prediction_resistance,
                              const unsigned char *pstr, size_t pstr_len,
                              const OSSL_PARAM params[])
{
    return RET_OSSL_OK;
}

static int osrand_uninstantiate(void *vctx)
{
    OSRAND_RAND_CTX *ctx = (OSRAND_RAND_CTX *)vctx;
    osrand_close_random_device(&ctx->rd);
    return RET_OSSL_OK;
}

/* RAND set parameters */
static int osrand_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    int ret;

    p = OSSL_PARAM_locate(params, "max_request");
    if (p != NULL) {
        ret = OSSL_PARAM_set_size_t(p, INT_MAX);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

static const OSSL_PARAM *osrand_gettable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *osrand_settable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END,
    };
    return params;
}

static int osrand_enable_locking(void *pctx)
{
    return RET_OSSL_OK;
}

static int osrand_lock(void *pctx)
{
    return RET_OSSL_OK;
}

static void osrand_unlock(void *pctx)
{
    /* nothing to do */
}

/* RAND methods */
static const OSSL_DISPATCH osrand_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))osrand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))osrand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))osrand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))osrand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))osrand_generate },
    { OSSL_FUNC_RAND_RESEED, (void (*)(void))osrand_reseed },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))osrand_lock },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))osrand_enable_locking },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))osrand_unlock },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))osrand_get_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
      (void (*)(void))osrand_gettable_ctx_params },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
      (void (*)(void))osrand_settable_ctx_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM osrand_algs[] = {
    { "CTR-DRBG", "provider=osrand", osrand_rand_functions },
    { "HASH-DRBG", "provider=osrand", osrand_rand_functions },
    { "HMAC-DRBG", "provider=osrand", osrand_rand_functions },
    { NULL, NULL, NULL }
};

/* Provider query */
static const OSSL_ALGORITHM *
osrand_query_operation(void *provctx, int operation_id, int *no_store)
{
    switch (operation_id) {
    case OSSL_OP_RAND:
        return osrand_algs;
    }
    return NULL;
}

/* Provider entry points */
static const OSSL_DISPATCH osrand_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
      (void (*)(void))osrand_query_operation },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))NULL },
    { 0, NULL }
};

static void osrand_get_core_dispatch_funcs(const OSSL_DISPATCH *in)
{
    const OSSL_DISPATCH *iter_in;

    for (iter_in = in; iter_in->function_id != 0; iter_in++) {
        switch (iter_in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            core_get_params = OSSL_FUNC_core_get_params(iter_in);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            core_new_error = OSSL_FUNC_core_new_error(iter_in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            core_set_error_debug = OSSL_FUNC_core_set_error_debug(iter_in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            core_vset_error = OSSL_FUNC_core_vset_error(iter_in);
            break;
        default:
            /* Ignore anything that is not used. */
            continue;
        }
    }
}

/* Set mode */
static int osrand_set_mode(OSRAND_PROV_CTX *ctx, const char *mode)
{
    if (mode != NULL) {
        if (strcmp(mode, OSRAND_MODE_GETRANDOM_NAME) == 0) {
            ctx->mode = OSRAND_MODE_GETRANDOM;
        } else if (strcmp(mode, OSRAND_MODE_DEVLRNG_NAME) == 0) {
            ctx->mode = OSRAND_MODE_DEVLRNG;
        } else if (strcmp(mode, OSRAND_MODE_DEVRANDOM_NAME) == 0) {
            ctx->mode = OSRAND_MODE_DEVRANDOM;
        } else {
            ctx->mode = OSRAND_MODE_GETRANDOM;
        }
    } else {
        ctx->mode = OSRAND_MODE_GETRANDOM;
    }
    return 1;
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    *provctx = NULL;

    osrand_get_core_dispatch_funcs(in);

    // Get provider params
    char *mode = NULL;
    OSSL_PARAM core_params[] = {
        OSSL_PARAM_construct_utf8_ptr(OSRAND_PARAM_MODE, &mode, sizeof(void *)),
        OSSL_PARAM_END,
    };
    core_get_params(handle, core_params);

    // Create provider context
    OSRAND_PROV_CTX *ctx = OPENSSL_zalloc(sizeof(OSRAND_PROV_CTX));
    if (ctx == NULL) {
        return RET_OSSL_ERR;
    }
    ctx->handle = handle;
    osrand_set_mode(ctx, mode);

    *provctx = ctx;
    *out = osrand_provider_functions;
    return 1;
}
