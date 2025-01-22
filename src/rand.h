/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   Copyright (C) 2025 Jakub Zelenka <simo@redhat.com>
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

extern const OSSL_DISPATCH osrand_rand_functions[];

#endif /* _RAND_H */
