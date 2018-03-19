

package cose


import (
	"errors"
	"bytes"
	"math/big"
	"crypto"
	"crypto/rsa"
	"crypto/ecdsa"
	"fmt"
	"log"
	"io"
	generated "github.com/g-k/go-cose/generated"
)

const (
	ContextSignature = "Signature"
	ContextSignature1 = "Signature1"
	ContextCounterSignature = "CounterSignature"
)

// COSESigner
type COSESigner struct {
	privateKey crypto.PrivateKey
}
// NewCOSESigner
// implements crypto.Signer
func NewCOSESigner(privateKey crypto.PrivateKey) (signer *COSESigner, err error) {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
	case *ecdsa.PrivateKey:
	case rsa.PrivateKey:
	case ecdsa.PrivateKey:
	default:
		return nil, errors.New("Could not return public key for Unrecognized private key type.")
	}
	return &COSESigner{
		privateKey: privateKey,
	}, nil
}
// Public
func (s *COSESigner) Public() (publicKey crypto.PublicKey) {
	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		return key.Public()
	case *ecdsa.PrivateKey:
		return key.Public()
	default:
		log.Fatal("Could not return public key for Unrecognized private key type.")
	}
	return
}
type SignOpts struct {
	HashFunc crypto.Hash
	GetSigner func(index int, signature COSESignature) (COSESigner, error)
}
// Sign returns a byte slice of the COSE signature
func (s *COSESigner) Sign(rand io.Reader, digest []byte, opts SignOpts) (signature []byte, err error) {
	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPSS(rand, key, opts.HashFunc, digest, nil)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("rsa.SignPSS error %s", err))
		}
		return sig, nil
	case *ecdsa.PrivateKey:
		// https://tools.ietf.org/html/rfc8152#section-8.1
		r, s, err := ecdsa.Sign(rand, key, digest)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("ecdsa.Sign error %s", err))
		}

		// assert r and s are the same length will be the same length
		// as the length of the key used for the signature process
		// fmt.Println(fmt.Printf("\nr: %+v\ns: %+v\n %+x", r, s, digest))

		// The signature is encoded by converting the integers into
		// byte strings of the same length as the key size.  The
		// length is rounded up to the nearest byte and is left padded
		// with zero bits to get to the correct length.  The two
		// integers are then concatenated together to form a byte
		// string that is the resulting signature.
		curveBits := key.Curve.Params().BitSize
		keyBytes := curveBits / 8
		if curveBits % 8 > 0 {
			keyBytes += 1
		}

		n := keyBytes
		sig := make([]byte, 0)
		sig = append(sig, I2OSP(r, n)...)
		sig = append(sig, I2OSP(s, n)...)

		return sig, nil
	default:
		return nil, errors.New("Unrecognized private key type.")
	}
	return
}
// Verifier returns a COSEVerifier using the COSESigners public key and a func that returns whether the key is valid?
func (s *COSESigner) Verifier(
	alg *generated.COSEAlgorithm,
	// getVerifierFunc (index int, signature COSESignature) (COSEVerifier, error)
) (verifier *COSEVerifier) {
	return &COSEVerifier{
		publicKey: s.Public(),
		opts: VerifierOpts{
			alg: alg,
		},
	}
}


// COSEVerifier
type COSEVerifier struct {
	publicKey crypto.PublicKey
	opts VerifierOpts
}
type VerifierOpts struct {
	alg *generated.COSEAlgorithm
	// keyFinder func (kid interface{}) (keyFound bool)
}
type VerifyOpts struct {
	GetVerifier func(index int, signature COSESignature) (COSEVerifier, error)
}
// Verify returns nil for success or an error
func (v *COSEVerifier) Verify(digest []byte, signature []byte) (err error) {
	switch key := v.publicKey.(type) {
	case *rsa.PublicKey:
		_, hash, err := getExpectedArgsForAlg(v.opts.alg)
		if err != nil {
			return err
		}

		err = rsa.VerifyPSS(key, hash, digest, signature, nil)
		if err != nil {
			return errors.New(fmt.Sprintf("verification failed rsa.VerifyPSS err %s", err))
		}
	case *ecdsa.PublicKey:
		keySize, err := getKeySizeForAlg(v.opts.alg)
		if err != nil {
			return err
		}

		// r and s from sig
		if len(signature) != 2 * keySize {
			return errors.New(fmt.Sprintf("invalid signature length: %d", len(signature)))
		}

		r := big.NewInt(0).SetBytes(signature[:keySize])
		s := big.NewInt(0).SetBytes(signature[keySize:])

		ok := ecdsa.Verify(key, digest, r, s)
		if ok {
			return nil
		} else {
			return errors.New("verification failed ecdsa.Verify")
		}
	default:
		return errors.New("Unrecognized publicKey type.")
	}
	return
}




// imperative functions on byte slices level

func buildAndCBOREncodeSigStructure(
	body_protected []byte,
	sign_protected []byte,
	external []byte,
	payload []byte,
) (ToBeSigned []byte, err error) {
	// 1.  Create a Sig_structure and populate it with the appropriate fields.
	//
	// Sig_structure = [
	//     context : "Signature" / "Signature1" / "CounterSignature",
	//     body_protected : empty_or_serialized_map,
	//     ? sign_protected : empty_or_serialized_map,
	//     external_aad : bstr,
	//     payload : bstr
	// ]
	sig_structure := []interface{}{
		ContextSignature,
		body_protected, // message.headers.EncodeProtected(),
		sign_protected, // message.signatures[0].headers.EncodeProtected(),
		external,
		payload,
	}

	// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
	//     byte string, using the encoding described in Section 14.
	ToBeSigned, err = CBOREncode(sig_structure)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("CBOREncode error encoding sig_structure: %s", err))
	}
	return ToBeSigned, nil
}

func hashSigStructure(ToBeSigned []byte, hash crypto.Hash) (digest []byte) {
	hasher := hash.New()
	_, _ = hasher.Write(ToBeSigned)  // Write() on hash never fails
	digest = hasher.Sum(nil)
	return digest
}

// https://github.com/r2ishiguro/vrf/blob/69d5bfb37b72b7b932ffe34213778bdb319f0438/go/vrf_ed25519/vrf_ed25519.go#L206
func I2OSP(b *big.Int, n int) []byte {
	os := b.Bytes()
	if n > len(os) {
		var buf bytes.Buffer
		buf.Write(make([]byte, n - len(os)))	// prepend 0s
		buf.Write(os)
		return buf.Bytes()
	} else {
		return os[:n]
	}
}
