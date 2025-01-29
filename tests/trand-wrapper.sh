#!/bin/bash -e
# Copyright (C) 2025 Jakub Zelenka <jakub.openssl@gmail.com>
# SPDX-License-Identifier: Apache-2.0

osr_test_dir=$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

function osr_run_test {
    osr_mode=$1
    osr_openssl_conf="${TESTBLDDIR}/openssl-$osr_mode.cnf"

    sed -e "s|__OPENSSL_MODULES_DIR__|${LIBSPATH}|g" \
        -e "s|__SHARED_EXT__|${SHARED_EXT}|g" \
        -e "s|__OSRAND_MODE__|${osr_mode}|g" \
        "${TESTSSRCDIR}/openssl.cnf.in" > "${osr_openssl_conf}"

    export OPENSSL_CONF=$osr_openssl_conf

    osr_log_file="$TESTBLDDIR/test-$osr_mode.log"
    rm -f $osr_log_file
    export OSRAND_PROVIDER_DEBUG="file:$osr_log_file,level:6"

    $TESTBLDDIR/trand

    # Verify log expectations
    if [[ "$osr_mode" == "getrandom" ]]; then
        grep -q "Initilazing OSRand provider" "$osr_log_file"
        grep -q "Setting getrandom mode" "$osr_log_file"
        grep -q "Generated 16 bytes using getrandom" "$osr_log_file"
    elif [[ "$osr_mode" == "devrandom" ]]; then
        grep -q "Initilazing OSRand provider" "$osr_log_file"
        grep -q "Setting devrandom mode" "$osr_log_file"
        grep -q "Opened random device" "$osr_log_file"
        grep -q "Generated 16 bytes from /dev/random device" "$osr_log_file"
        grep -q "Closing random device" "$osr_log_file"
    fi
}

# Test getrandom
osr_run_test getrandom

# Test devrandom
osr_run_test devrandom

