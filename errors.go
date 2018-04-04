package cose

import (
	"errors"
)

var (
	AlgNotFoundErr            = errors.New("Error fetching alg")
	ECDSAVerificationErr      = errors.New("verification failed ecdsa.Verify")
	RSAPSSVerificationErr     = errors.New("verification failed rsa.VerifyPSS err crypto/rsa: verification error")
	MissingCOSETagForLabelErr = errors.New("No common COSE tag for label")
	MissingCOSETagForTagErr   = errors.New("No common COSE label for tag")
	NilSigHeaderErr           = errors.New("Signature.headers is nil")
	NilSigProtectedHeadersErr = errors.New("Signature.headers.protected is nil")
	NilSignaturesErr          = errors.New("SignMessage.signatures is nil. Use AddSignature to add one")
	NoSignaturesErr           = errors.New("No signatures to sign the message. Use AddSignature to add them")
	NoSignerFoundErr          = errors.New("No signer found")
	NoVerifierFoundErr        = errors.New("No verifier found")
	UnavailableHashFuncErr    = errors.New("hash function is not available")
	UnknownPrivateKeyTypeErr  = errors.New("Unrecognized private key type")
	UnknownPublicKeyTypeErr   = errors.New("Unrecognized public key type")
)
