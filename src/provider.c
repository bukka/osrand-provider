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

/* Modes for selecting the source */
typedef enum {
    OSRAND_MODE_GETRANDOM,
    OSRAND_MODE_DEVLRNG,
    OSRAND_MODE_DEVRANDOM
} OSRAND_MODE;

typedef struct {
    int fd;
    dev_t dev;
    ino_t ino;
    mode_t mode;
    dev_t rdev;
} OSRAND_RANDOM_DEVICE;

/* Context structure */
typedef struct {
    OSRAND_MODE mode; /* Current mode */
    OSRAND_RANDOM_DEVICE rd; /* Random device if device used */
} OSRAND_CONTEXT;

/* Check whether random device fd is still open and device is valid */
static int osrand_check_random_device(OSRAND_RANDOM_DEVICE *rd)
{
    struct stat st;

    return rd->fd != -1
           && fstat(rd->fd, &st) != -1
           && rd->dev == st.st_dev
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
    if (osrand_check_random_device(rd))
        return rd->fd;

    /* open the random device ... */
    if ((rd->fd = open(device_path, O_RDONLY)) == -1)
        return rd->fd;

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
    if (osrand_check_random_device(rd))
        close(rd->fd);
    rd->fd = -1;
}

/* Generate random bytes using a device file */
static int osrand_generate_from_device(OSRAND_CONTEXT *ctx,
                                       const char *device_path,
                                       unsigned char *buf, size_t buflen)
{
    int fd = osrand_get_random_device(&ctx->rd, device_path);
    if (fd == -1) {
        return RET_OSSL_ERR; /* Failed to retrieving the device */
    }

    ssize_t total_read = 0;
    while (total_read < (ssize_t)buflen) {
        ssize_t ret = read(fd, buf + total_read, buflen - total_read);
        if (ret <= 0) {
            if (ret == -1 && errno == EINTR) {
                continue; /* Retry on interrupt */
            }
            return RET_OSSL_ERR; /* Read error */
        }
        total_read += ret;
    }

    return RET_OSSL_OK;
}

/* Generate random bytes using getrandom */
static int osrand_generate_using_getrandom(unsigned char *buf, size_t buflen)
{
    ssize_t ret = getrandom(buf, buflen, 0);
    return (ret == -1 || (size_t)ret != buflen) ? 0 : 1;
}

/* RAND generate function */
static int osrand_generate(void *vctx, unsigned char *buf, size_t buflen,
                           unsigned int strength, int prediction_resistance)
{
    OSRAND_CONTEXT *ctx = (OSRAND_CONTEXT *)vctx;
    (void)strength;
    (void)prediction_resistance;

    switch (ctx->mode) {
    case OSRAND_MODE_GETRANDOM:
        return osrand_generate_using_getrandom(buf, buflen);
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
    OSRAND_CONTEXT *ctx = OPENSSL_malloc(sizeof(OSRAND_CONTEXT));
    if (ctx == NULL) return NULL;
    ctx->mode = OSRAND_MODE_GETRANDOM; /* Default to getrandom */
    return ctx;
}

/* RAND free context */
static void osrand_freectx(void *vctx)
{
    OSRAND_CONTEXT *ctx = (OSRAND_CONTEXT *)vctx;
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
    OSRAND_CONTEXT *ctx = (OSRAND_CONTEXT *)vctx;
    osrand_close_random_device(&ctx->rd);
    return RET_OSSL_OK;
}


/* RAND set parameters */
static int osrand_get_params(void *vctx, OSSL_PARAM params[])
{
    OSRAND_CONTEXT *ctx = (OSRAND_CONTEXT *)vctx;
    OSSL_PARAM *p;
    int ret;

    p = OSSL_PARAM_locate(params, "mode");
    if (p != NULL) {
        switch (ctx->mode) {
            case OSRAND_MODE_GETRANDOM:
                ret = OSSL_PARAM_set_utf8_string(p, "getrandom");
                break;
            case OSRAND_MODE_DEVLRNG:
                ret = OSSL_PARAM_set_utf8_string(p, "devlrng");
                break;
            case OSRAND_MODE_DEVRANDOM:
                ret = OSSL_PARAM_set_utf8_string(p, "devrandom");
                break;
            default:
                ret = 0;
        }
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    p = OSSL_PARAM_locate(params, "max_request");
    if (p != NULL) {
        ret = OSSL_PARAM_set_size_t(p, INT_MAX);
        if (ret != RET_OSSL_OK) {
            return ret;
        }
    }

    return RET_OSSL_OK;
}

/* RAND set parameters */
static int osrand_set_params(void *vctx, const OSSL_PARAM params[])
{
    OSRAND_CONTEXT *ctx = (OSRAND_CONTEXT *)vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, "mode");
    if (p != NULL && p->data_type == OSSL_PARAM_UTF8_STRING) {
        if (strcmp(p->data, "getrandom") == 0) {
            ctx->mode = OSRAND_MODE_GETRANDOM;
        } else if (strcmp(p->data, "devlrng") == 0) {
            ctx->mode = OSRAND_MODE_DEVLRNG;
        } else if (strcmp(p->data, "devrandom") == 0) {
            ctx->mode = OSRAND_MODE_DEVRANDOM;
        } else {
            return 0; /* Invalid mode */
        }
    }
    return 1;
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
    { OSSL_FUNC_RAND_RESEED, (void (*)(void))osrand_reseed},
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))osrand_lock },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))osrand_enable_locking },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))osrand_unlock },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))osrand_get_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void))osrand_set_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM osrand_algs[] = {
    { "CTR-DRBG", "provider=osrand", osrand_rand_functions },
    { "HASH-DRBG", "provider=osrand", osrand_rand_functions },
    { "HMAC-DRBG", "provider=osrand", osrand_rand_functions },
    { NULL, NULL, NULL }
};

/* Provider query */
static const OSSL_ALGORITHM *osrand_query_operation(void *provctx,
                                                    int operation_id,
                                                    int *no_store)
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

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    *out = osrand_provider_functions;
    *provctx = NULL;
    return 1;
}
