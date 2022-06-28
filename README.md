easypki
======

> this is an installable fork of google/easypki
> this have required a new package name because of a fork
> `github.com/mainnika/easypki`

Easy Public Key Infrastructure intends to provide most of the components needed
to manage a PKI, so you can either use the API in your automation, or use the
CLI.

# API

```
import "github.com/mainnika/easypki"
```

# CLI

Current implementation of the CLI uses the local store and uses a structure
compatible with openssl, so you are not restrained.

```
# Get the CLI:
GO111MODULE=on go get github.com/mainnika/easypki/cmd/easypki@v22.06.28


# You can also pass the following through arguments if you do not want to use
# env variables.
export PKI_ROOT=/tmp/pki
export PKI_ORGANIZATION="Acme Inc."
export PKI_ORGANIZATIONAL_UNIT=IT
export PKI_COUNTRY=US
export PKI_LOCALITY="Agloe"
export PKI_PROVINCE="New York"

mkdir $PKI_ROOT

# Create the root CA:
easypki create --filename root --ca "Acme Inc. Certificate Authority"

# In the following commands, ca-name corresponds to the filename containing
# the CA.

# Create a server certificate for blog.acme.com and www.acme.com:
easypki create --ca-name root --dns blog.acme.com --dns www.acme.com www.acme.com

# Create an intermediate CA:
easypki create --ca-name root --filename intermediate --intermediate "Acme Inc. - Internal CA"

# Create a wildcard certificate for internal use, signed by the intermediate ca:
easypki create --ca-name intermediate --dns "*.internal.acme.com" "*.internal.acme.com"

# Create a client certificate:
easypki create --ca-name intermediate --client --email bob@acme.com bob@acme.com

# Revoke the www certificate.
easypki revoke $PKI_ROOT/root/certs/www.acme.com.crt

# Generate a CRL expiring in 1 day (PEM Output on stdout):
easypki crl --ca-name root --expire 1
```
You will find the generated certificates in `$PKI_ROOT/ca_name/certs/` and
private keys in `$PKI_ROOT/ca_name/keys/`

For more info about available flags, checkout out the help `easypki -h`.

# Disclaimer

This is not an official Google product.
