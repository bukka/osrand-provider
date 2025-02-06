/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   Copyright (C) 2025 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

/* This is mostly copied from PKCS11 provider for convenience. */

/* for strndup we need to define POSIX_C_SOURCE */
#define _POSIX_C_SOURCE 200809L
#include "provider.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int osrand_debug_level = -1;
static FILE *stddebug = NULL;

/* this function relies on being called by OSRAND_debug, after
 * an __atomic_compare_exchange_n sets osrand_debug_level to -1,
 * This allows only 1 thread to ever init, as any other thread
 * would see debugging as disabled. This means some debugging may
 * be lost but will not risk multiplt thread stopming on each
 * other to open the debug file */
void osrand_debug_init(void)
{
    /* The ',' character should not be used in the path as it will
     * break tokenization, we do not provide any escaping */
    const char *env = getenv("OSRAND_PROVIDER_DEBUG");
    const char *next;
    char fname[1024];
    int dbg_level = 0;
    int orig;
    if (env) {
        do {
            next = strchr(env, ',');
            if (strncmp(env, "file:", 5) == 0) {
                int len;
                if (stddebug != NULL && stddebug != stderr) {
                    fclose(stddebug);
                }
                if (next) {
                    len = next - env - 5;
                } else {
                    len = strlen(env + 5);
                }
                memcpy(fname, env + 5, len);
                fname[len] = '\0';
                stddebug = fopen(fname, "a");
                if (stddebug == NULL) {
                    goto done;
                }
            } else if (strncmp(env, "level:", 6) == 0) {
                dbg_level = atoi(env + 6);
            }
            if (next) {
                env = next + 1;
            }
        } while (next);

        if (dbg_level < 1) {
            dbg_level = 1;
        }
        if (stddebug == NULL) {
            stddebug = stderr;
        }
    }

done:
    /* set value to osrand_debug_level atomically */
    __atomic_exchange(&osrand_debug_level, &dbg_level, &orig, __ATOMIC_SEQ_CST);
}

void osrand_debug(const char *file, int line, const char *func, const char *fmt,
                  ...)
{
    const char newline[] = "\n";
    va_list args;

    if (file) {
        fprintf(stddebug, "[%s:%d] ", file, line);
    }
    if (func) {
        fprintf(stddebug, "%s(): ", func);
    }
    va_start(args, fmt);
    vfprintf(stddebug, fmt, args);
    va_end(args);
    fwrite(newline, 1, 1, stddebug);
    fflush(stddebug);
}
