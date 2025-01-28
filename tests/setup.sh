#!/bin/bash -e
# Copyright (C) 2025 Jakub Zelenka <jakub.openssl@gmail.com>
# SPDX-License-Identifier: Apache-2.0

TMPPDIR="${TESTBLDDIR}"
OPENSSL_CONF_GETRANDOM=${TMPPDIR}/openssl-getrandom.cnf
OPENSSL_CONF_DEVRANDOM=${TMPPDIR}/openssl-devrandom.cnf

sed -e "s|__OPENSSL_MODULES_DIR__|${LIBSPATH}|g" \
    -e "s|__SHARED_EXT__|${SHARED_EXT}|g" \
    -e "s|__OSRAND_MODE__|getrandom|g" > "${OPENSSL_CONF_GETRANDOM}"

sed -e "s|__OPENSSL_MODULES_DIR__|${LIBSPATH}|g" \
    -e "s|__SHARED_EXT__|${SHARED_EXT}|g" \
    -e "s|__OSRAND_MODE__|getrandom|g" > "${OPENSSL_CONF_DEVRANDOM}"
