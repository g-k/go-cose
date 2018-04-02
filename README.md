# go-cose

[![Build Status](https://travis-ci.org/mozilla-services/go-cose.svg?branch=master)](https://travis-ci.org/mozilla-services/go-cose)
[![Coverage Status](https://coveralls.io/repos/github/mozilla-services/go-cose/badge.svg)](https://coveralls.io/github/mozilla-services/go-cose)

A [COSE](https://tools.ietf.org/html/rfc8152) library for go.

It currently supports signing and verifying the SignMessage type with the ES{256,384,512} and PS256 algorithms.

[API docs](https://godoc.org/go.mozilla.org/cose)

## Usage

### Install

```console
go get -u go.mozilla.org/cose
```

### Signing a message

```golang
// create a signer


```

### Verifying a message

```golang
// create a verifier


```

## Development

Running tests:

```console
make godep golint  # skip if you already have them
make install
go test # note that the rust tests will fail
```

The [cose-rust](https://github.com/g-k/cose-rust) tests run in CI. To run them locally:

1. Install [rust and cargo](https://www.rustup.rs/)
1. On OSX, you might need to:
  1. `brew install nss` [nss](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS)
  1. Add `NSS_LIB_DIR` to the cmd in `sign_verify_cose_rust_cli_test.go` e.g. `cmd.Env = append(os.Environ(), "NSS_LIB_DIR=/usr/local/opt/nss/lib", "RUSTFLAGS=-A dead_code -A unused_imports")`
1. It can also be helpful to add the following to print output from the cmd too:

	```golang
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	```
