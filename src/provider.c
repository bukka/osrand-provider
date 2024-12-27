#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/random.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define PROVIDER_NAME "OSRand"
#define PROVIDER_VERSION "0.1"

/* Modes for selecting the source */
typedef enum {
    OSRAND_MODE_GETRANDOM,
    OSRAND_MODE_DEVLRNG,
    OSRAND_MODE_DEVRANDOM
} OSRAND_MODE;

/* Context structure */
typedef struct {
    OSRAND_MODE mode; /* Current mode */
} OSRAND_CONTEXT;

/* Generate random bytes using a device file */
static int osrand_generate_from_device(const char *device_path,
                                       unsigned char *buf, size_t buflen)
{
    int fd = open(device_path, O_RDONLY);
    if (fd == -1) {
        return 0; /* Failed to open device - most likely because lrng is not available */
    }

    ssize_t total_read = 0;
    while (total_read < (ssize_t)buflen) {
        ssize_t ret = read(fd, buf + total_read, buflen - total_read);
        if (ret <= 0) {
            if (ret == -1 && errno == EINTR) {
                continue; /* Retry on interrupt */
            }
            close(fd);
            return 0; /* Read error */
        }
        total_read += ret;
    }

    close(fd);
    return 1; /* Success */
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
        return osrand_generate_from_device("/dev/lrng", buf, buflen);
    case OSRAND_MODE_DEVRANDOM:
        return osrand_generate_from_device("/dev/random", buf, buflen);
    default:
        return 0; /* Unknown mode */
    }
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
    OPENSSL_free(ctx);
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

/* RAND methods */
static const OSSL_DISPATCH osrand_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))osrand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))osrand_freectx },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))osrand_generate },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void))osrand_set_params },
    { 0, NULL }
};

/* Provider initialization */
static int osrand_provider_init(const OSSL_CORE_HANDLE *handle,
                                const OSSL_DISPATCH *in,
                                const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *provctx = NULL;
    *out = osrand_rand_functions;
    return 1;
}

/* Provider entry points */
static const OSSL_DISPATCH osrand_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION,
      (void (*)(void))osrand_provider_init },
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
