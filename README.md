[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# osrand-provider

This is an OpenSSL 3.x provider that provides direct access to the OS random
API, completely bypassing the OpenSSL PRNG. In addition, it provides access
to the LRNG project (requires LRNG kernel patches).

## Setup

### Prerequisites

This package requires the following:
- OpenSSL 3.0.7+ libraries and development headers
- OpenSSL tools (for testing)
- A C compiler that supports at least C11 semantics
- meson
- pkg-config

### Build

The usual commands to build are:
- `meson setup builddir`
- `meson compile -C builddir`
- `meson test -C builddir`

To link with OpenSSL installed in a custom path, set
`PKG_CONFIG_PATH` or `CFLAGS`/`LDFLAGS` environment variables accordingly
during the `meson setup` step. For example, assume OpenSSL is installed
under an absolute path `$OPENSSL_DIR`.

If you rely on pkg-config, point `PKG_CONFIG_PATH` to a directory
where `libcrypto.pc` or `openssl.pc` can be found.

- `PKG_CONFIG_PATH="$OPENSSL_DIR/lib64/pkgconfig" meson setup builddir`

Otherwise, you can set `CFLAGS`/`LDFLAGS`:

- `CFLAGS="-I$OPENSSL_DIR/include" LDFLAGS="-L$OPENSSL_DIR/lib64" meson setup builddir`

### Installation

The usual command to install is:

- `meson install -C builddir`

Or simply copy the `src/osrand.so` (or `src/osrand.dylib` on Mac) in the
appropriate directory for your OpenSSL installation.

## Usage

Example configurations and basic use cases can be found in [HOWTO](HOWTO.md).

### Configuration via openssl.cnf

Once you have installed the module you need to change OpenSSL's configuration to
be able to load the provider.

The example configuration can look as follows:

```
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
random = random_sect

[provider_sect]
default = default_sect
osrand = osrand_sect

[default_sect]
activate = 1

[osrand_sect]
module = /path/to/osrand.so
activate = 1
#osrand-mode = devrandom

[random_sect]
random = OS-DRBG
```

It is important to activate the default provider when enabling another provider
(in this case, osrand); otherwise, it will not be activated. The random section
is also crucial, as the default random is CRT-DRBG, so OS-DRBG needs to be
selected explicitly.

The `osrand-mode` defaults to `getrandom`, but if there is a need to
use the `/dev/random` device, it can be set to `devrandom` (simply uncommenting
the field in the example). Additionally, the `devlrng` mode is available,
which will use the `/dev/lrng` device. This requires a patched kernel with
[LRNG patches](https://github.com/smuellerDD/lrng).

The module path must also be correctly set. Typically, it will be
located in the `ossl-modules` directory of the installation. This path is
displayed during installation when running the `meson install` command.
