/* Copyright (C) 2025 Jakub Zelenka <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#include "provider.h"
#include "rand.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>


static OSSL_FUNC_core_get_params_fn *core_get_params = NULL;
static OSSL_FUNC_core_new_error_fn *core_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn *core_vset_error = NULL;


void osrand_raise(OSRAND_PROV_CTX *ctx, const char *file, int line,
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
