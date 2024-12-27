## How To use the PKCS#11 provider

### Configuration via openssl.cnf

Once you have installed the module you need to change OpenSSL's configuration to
be able to load the provider.

In openssl.cnf add the following section:

```
[osrand_sect]
module = /path/to/osrand.so
activate = 1
```
Optionally enable LRNG:
```
mode = devlrng
```

Once the section is properly constructed add the following statement to the
provider section. If a provider section does not exist, make sure to create one
with all the needed providers (at least the default provider will be needed - 
remember to activate it, otherwise the _openssl_ command will not behave 
correctly):

```
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
osrand = osrand_sect

[default_sect]
activate = 1
```

See CONFIG(5OSSL) manpage for more information on the openssl.cnf file.
