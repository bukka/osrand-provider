/* Copyright (C) 2025 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _RAND_H
#define _RAND_H

#include "provider.h"

typedef struct {
    int fd;
    dev_t dev;
    ino_t ino;
    mode_t mode;
    dev_t rdev;
} OSRAND_RANDOM_DEVICE;

/* RAND context structure */
typedef struct {
    /* Provider context */
    OSRAND_PROV_CTX *provctx;
    /* Random device if device used */
    OSRAND_RANDOM_DEVICE rd;
} OSRAND_RAND_CTX;

int osrand_generate(void *vctx, unsigned char *buf, size_t buflen,
                    unsigned int strength, int prediction_resistance);
int osrand_reseed(void *pctx, int prediction_resistance,
                  const unsigned char *entropy, size_t ent_len,
                  const unsigned char *adin, size_t adin_len);
void *osrand_newctx(void *provctx);
void osrand_freectx(void *vctx);
int osrand_instantiate(void *vctx, unsigned int strength,
                       int prediction_resistance, const unsigned char *pstr,
                       size_t pstr_len, const OSSL_PARAM params[]);
int osrand_uninstantiate(void *vctx);
int osrand_get_ctx_params(void *vctx, OSSL_PARAM params[]);
const OSSL_PARAM *osrand_gettable_ctx_params(void *ctx, void *prov);
const OSSL_PARAM *osrand_settable_ctx_params(void *ctx, void *prov);
int osrand_enable_locking(void *pctx);
int osrand_lock(void *pctx);
void osrand_unlock(void *pctx);

#endif /* _RAND_H */
