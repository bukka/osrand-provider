/* Copyright (C) 2025 Jakub Zelenka <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <openssl/core.h>

#define PROVIDER_NAME "OSRand"
#define PROVIDER_VERSION "0.1"

#define RET_OSSL_OK 1
#define RET_OSSL_ERR 0
#define RET_OSSL_BAD -1

#define OSRAND_E_DEVICE_OPEN_FAIL 1
#define OSRAND_E_DEVICE_READ_FAIL 2
#define OSRAND_E_GETRANDOM_FAIL 3

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

/* Provider context structure */
typedef struct {
    /* Current mode */
    OSRAND_MODE mode;
    /* Provider handles */
    const OSSL_CORE_HANDLE *handle;
} OSRAND_PROV_CTX;

#include "debug.h"

#define OSRAND_raise(ctx, errnum, format, ...) \
    do { \
        osrand_raise((ctx), OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, (errnum), \
                    format, ##__VA_ARGS__); \
        OSRAND_debug("Error: " format, ##__VA_ARGS__); \
    } while(0)

void osrand_raise(OSRAND_PROV_CTX *ctx, const char *file, int line,
                  const char *func, int errnum, const char *fmt, ...);

#endif /* _PROVIDER_H */
