/* Copyright (C) 2025 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "rand.h"

#include <sys/random.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>

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
    if ((rd->fd = open(device_path, O_RDONLY)) == -1) return -1;

    /* ... and cache its relevant stat(2) data */
    if (fstat(rd->fd, &st) != -1) {
        rd->dev = st.st_dev;
        rd->ino = st.st_ino;
        rd->mode = st.st_mode;
        rd->rdev = st.st_rdev;
        OSRAND_debug("Opened random device fd %d", rd->fd);
    } else {
        OSRAND_debug("New random device fd %d stat failed", rd->fd);
        close(rd->fd);
        rd->fd = -1;
    }

    return rd->fd;
}

/* Close a random device making sure it is a random device */
static void osrand_close_random_device(OSRAND_RANDOM_DEVICE *rd)
{
    if (osrand_check_random_device(rd)) {
        OSRAND_debug("Closing random device fd %d", rd->fd);
        close(rd->fd);
    }
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

    OSRAND_debug("Generated %zd bytes from %s device", total_read, device_path);

    return RET_OSSL_OK;
}

/* Generate random bytes using getrandom */
static int osrand_generate_using_getrandom(OSRAND_RAND_CTX *ctx,
                                           unsigned char *buf, size_t buflen)
{
    ssize_t ret = getrandom(buf, buflen, 0);
    if (ret < 0) {
        OSRAND_raise(ctx->provctx, OSRAND_E_DEVICE_READ_FAIL,
                     "Failed to get %zu bytes using getrandom due error",
                     buflen);
        return 0;
    } else if ((size_t)ret != buflen) {
        OSRAND_raise(
            ctx->provctx, OSRAND_E_DEVICE_READ_FAIL,
            "Failed to get %zu bytes using getrandom, only %zd received",
            buflen, ret);
        return 0;
    }

    OSRAND_debug("Generated %zu bytes using getrandom", buflen);

    return ((size_t)ret != buflen) ? 0 : 1;
}

/* RAND generate function */
int osrand_generate(void *vctx, unsigned char *buf, size_t buflen,
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
int osrand_reseed(void *pctx, int prediction_resistance,
                         const unsigned char *entropy, size_t ent_len,
                         const unsigned char *adin, size_t adin_len)
{
    return RET_OSSL_OK;
}

/* RAND new context */
void *osrand_newctx(void *provctx)
{
    OSRAND_RAND_CTX *ctx = OPENSSL_malloc(sizeof(OSRAND_RAND_CTX));
    if (ctx == NULL) return NULL;
    ctx->rd.fd = -1;
    ctx->provctx = provctx;

    OSRAND_debug("Creating new RAND context");

    return ctx;
}

/* RAND free context */
void osrand_freectx(void *vctx)
{
    OSRAND_RAND_CTX *ctx = (OSRAND_RAND_CTX *)vctx;

    osrand_close_random_device(&ctx->rd);

    OSRAND_debug("Freeing RAND context");
    OPENSSL_free(ctx);
}

int osrand_instantiate(void *vctx, unsigned int strength,
                              int prediction_resistance,
                              const unsigned char *pstr, size_t pstr_len,
                              const OSSL_PARAM params[])
{
    return RET_OSSL_OK;
}

int osrand_uninstantiate(void *vctx)
{
    OSRAND_RAND_CTX *ctx = (OSRAND_RAND_CTX *)vctx;
    osrand_close_random_device(&ctx->rd);
    return RET_OSSL_OK;
}

/* RAND set parameters */
int osrand_get_ctx_params(void *vctx, OSSL_PARAM params[])
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

const OSSL_PARAM *osrand_gettable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END,
    };
    return params;
}

const OSSL_PARAM *osrand_settable_ctx_params(void *ctx, void *prov)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END,
    };
    return params;
}

int osrand_enable_locking(void *pctx)
{
    return RET_OSSL_OK;
}

int osrand_lock(void *pctx)
{
    return RET_OSSL_OK;
}

void osrand_unlock(void *pctx)
{
    /* nothing to do */
}


