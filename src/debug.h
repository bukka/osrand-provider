/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   Copyright (C) 2025 Jakub Zelenka <jakub.openssl@gmail.com>
   SPDX-License-Identifier: Apache-2.0 */

extern int osrand_debug_level;

#define OSRAND_debug(...) \
    do { \
        if (osrand_debug_level < 0) { \
            osrand_debug_init(); \
        } \
        if (osrand_debug_level > 0) { \
            osrand_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC, \
                         __VA_ARGS__); \
        } \
    } while (0)

void osrand_debug_init(void);
void osrand_debug(const char *file, int line, const char *func, const char *fmt,
                  ...);
