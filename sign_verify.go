
package cose

import (
	"bytes"
	"math/big"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	// "log"
	"io"
	// codec "github.com/ugorji/go/codec"
)

const (
	ContextSignature = "Signature"
	ContextSignature1 = "Signature1"
	ContextCounterSignature = "CounterSignature"
)

// COSESignMessage https://tools.ietf.org/html/rfc8152#section-4.1
type COSESignMessage struct {
	headers *COSEHeaders
	payload []byte
	signatures []COSESignature
}
func NewCOSESignMessage() (msg COSESignMessage) {
	msg = COSESignMessage{
		headers: &COSEHeaders{
			protected: map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		payload: []byte(""),
		signatures: []COSESignature{
			{
				headers: &COSEHeaders{
					protected: map[interface{}]interface{}{},
					unprotected: map[interface{}]interface{}{},
				},
				signature: nil,
			},
		},
	}
	return msg
}

// COSESignature https://tools.ietf.org/html/rfc8152#section-4.1
type COSESignature struct {
	headers *COSEHeaders
	signature []byte
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

func hashSigStructure(message *COSESignMessage, key *ecdsa.PublicKey) []byte {
	if message.signatures == nil {
		panic("nil sigs")
	} else if len(message.signatures) < 1 {
		panic("no sig to hash")
	}

	sig_structure := []interface{}{
		ContextSignature,
		message.headers.EncodeProtected(),
		message.signatures[0].headers.EncodeProtected(),
		[]byte(""),  // TODO: pass as arg
		message.payload,
	}
	ToBeSigned := CBOREncode(sig_structure)

	var hash crypto.Hash

	// ES256
	// expectedBitSize := 256
	hash = crypto.SHA256

	// TODO: if provided privateKey verify alg, bitsize, and supported key_ops in protected

	hasher := hash.New()

	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(ToBeSigned)
	hashed := hasher.Sum(nil)

	return hashed
}


// TODO: rewrite as Signer(kid, alg key config).Sign(payload, ext_data)
// https://tools.ietf.org/html/rfc8152#section-4
func Sign(message *COSESignMessage, key *ecdsa.PrivateKey, randReader io.Reader) (result *COSESignMessage, err error, ToBeSigned []byte) {
	// Signing and Verification Process
	// https://tools.ietf.org/html/rfc8152#section-4.4
	//
	// 1.  Create a Sig_structure and populate it with the appropriate fields.
	// Sig_structure = [
	//     context : "Signature" / "Signature1" / "CounterSignature",
	//     body_protected : empty_or_serialized_map,
	//     ? sign_protected : empty_or_serialized_map,
	//     external_aad : bstr,
	//     payload : bstr
	// ]
	sig_structure := []interface{}{
		ContextSignature,
		message.headers.EncodeProtected(),
		message.signatures[0].headers.EncodeProtected(),
		[]byte(""),  // TODO: pass as arg
		message.payload,
	}

	// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
	//     byte string, using the encoding described in Section 14.
	ToBeSigned = CBOREncode(sig_structure)
	fmt.Println(fmt.Printf("ToBeSigned %+x", ToBeSigned))

	// 3.  Call the signature creation algorithm passing in K (the key to
	//     sign with), alg (the algorithm to sign with), and ToBeSigned (the
	//     value to sign).
	if message.signatures[0].headers.protected["alg"] != "ES256" {
		panic("Not implemented.")
	}

	var hash crypto.Hash

	// ES256
	// expectedBitSize := 256
	hash = crypto.SHA256

	// TODO: if provided privateKey verify alg, bitsize, and supported key_ops in protected
	curveBits := key.Curve.Params().BitSize

	hasher := hash.New()

	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(ToBeSigned)
	hashed := hasher.Sum(nil)
	fmt.Println(fmt.Printf("hashed %+x", hashed))

	// https://tools.ietf.org/html/rfc8152#section-8.1
	r, s, err := ecdsa.Sign(randReader, key, hashed)
	if err != nil {
		panic(fmt.Errorf("ecdsa.Sign error %s", err))
	}
	// assert r and s are the same length will be the same length as the length of the key used for the signature process

	fmt.Println(fmt.Printf("\nr: %+v\ns: %+v\n %+x", r, s, hashed))

	// The signature is encoded by converting the integers into
	// byte strings of the same length as the key size.  The
	// length is rounded up to the nearest byte and is left padded
	// with zero bits to get to the correct length.  The two
	// integers are then concatenated together to form a byte
	// string that is the resulting signature.
	keyBytes := curveBits / 8
	if curveBits % 8 > 0 {
		keyBytes += 1
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	fmt.Println(fmt.Printf("\nr: %+x\ns: %+x\n", rBytes, sBytes))

	// fmt.Println(fmt.Printf("\nPadded\nr: %+x\ns: %+x\n", rBytes, sBytes))

	n := keyBytes
	sig := make([]byte, 0)
	sig = append(sig, I2OSP(r, n)...)
	sig = append(sig, I2OSP(s, n)...)

	// 4.  Place the resulting signature value in the 'signature' field of the array.
	message.signatures[0].signature = sig
	// fmt.Println(fmt.Printf("%+v", message))
	return message, nil, ToBeSigned
}

func Verify(message *COSESignMessage, publicKey *ecdsa.PublicKey) (ok bool, err error) {
	hashed := hashSigStructure(message, publicKey)

	// ES256 / sha256
	keySize := 32

	// r and s from sig
	signature := message.signatures[0].signature
	fmt.Println(fmt.Printf("(Verify) signature %x %d", signature, len(signature) / 8))
	if len(signature) != 2 * keySize {
		panic(fmt.Sprintf("invalid signature length: %d", len(signature)))
	}

	r := big.NewInt(0).SetBytes(signature[:keySize])
	s := big.NewInt(0).SetBytes(signature[keySize:])

	return ecdsa.Verify(publicKey, hashed, r, s), nil
}
