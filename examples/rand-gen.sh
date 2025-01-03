#!/bin/bash

# Example for custom path OpenSSL build

osr_example_dir=$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

if [ -z "$OPENSSL_DIR" ]; then
    OPENSSL_DIR=/usr/local/ssl
    echo "Sertting openssl dir to $OPENSSL_DIR"
fi
if [ ! -d "$OPENSSL_DIR" ]; then
    echo "OPENSSL_DIR does not exist"
    exit 1
fi

export OPENSSL_CONF="$osr_example_dir/openssl.cnf"
export OPENSSL_CONF_IN="$OPENSSL_CONF.in"

sed "s|__OPENSSL_DIR__|$OPENSSL_DIR/lib64/ossl-modules|g" $OPENSSL_CONF_IN > $OPENSSL_CONF

echo "Using OPENSSL_CONF=$OPENSSL_CONF"

export LD_LIBRARY_PATH=$OPENSSL_DIR/lib64

echo $OPENSSL_DIR/bin/openssl rand -hex 16
$OPENSSL_DIR/bin/openssl rand -provider osrand -hex 16
