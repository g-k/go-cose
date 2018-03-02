
package cose

import (
	"errors"
	"bytes"
	"math/big"
	"crypto"
	"crypto/ecdsa"
	"fmt"
	// "log"
	"io"
)

const (
	ContextSignature = "Signature"
	ContextSignature1 = "Signature1"
	ContextCounterSignature = "CounterSignature"
)

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


// COSESignature https://tools.ietf.org/html/rfc8152#section-4.1
type COSESignature struct {
	headers *COSEHeaders
	signature []byte
}
func NewCOSESignature() (s *COSESignature) {
	return &COSESignature{
		headers: &COSEHeaders{
			protected: map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		signature: nil,
	}
}
func (m *COSESignature) SetHeaders(h *COSEHeaders) {
	m.headers = h
}
func (m *COSESignature) Decode(o interface {}) {
	array, ok := o.([]interface {})
	if !ok {
		panic(fmt.Sprintf("error decoding sigArray; got %T", array))
	}
	if len(array) != 3 {
		panic(fmt.Sprintf("can only decode COSESignature with 3 items; got %d", len(array)))
	}

	err := m.headers.DecodeProtected(array[0])
	if err != nil {
		panic(fmt.Sprintf("error decoding protected header bytes; got %s", err))
	}
	err = m.headers.DecodeUnprotected(array[1])
	if err != nil {
		panic(fmt.Sprintf("error decoding unprotected header map; got %s", err))
	}

	signature, ok := array[2].([]byte)
	if !ok {
		panic(fmt.Sprintf("unable to decode COSE signature expecting decode from interface{}; got %T", array[2]))
	}
	m.signature = signature
}


// COSESignMessage https://tools.ietf.org/html/rfc8152#section-4.1
type COSESignMessage struct {
	headers *COSEHeaders
	payload []byte
	signatures []COSESignature
}
func NewCOSESignMessage(payload []byte) (msg COSESignMessage) {
	msg = COSESignMessage{
		headers: &COSEHeaders{
			protected: map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		payload: payload,
		signatures: []COSESignature{},
	}
	return msg
}
func (m *COSESignMessage) AddSignature(s *COSESignature) {
	m.signatures = append(m.signatures, *s)
}
func (m *COSESignMessage) SetHeaders(h *COSEHeaders) {
	m.headers = h
}


func hashSigStructure(
	message *COSESignMessage,
	key *ecdsa.PublicKey,
	external []byte,
) (hashed []byte, ToBeSigned []byte, err error) {
	if message == nil {
		return nil, nil, errors.New("nil cose sign message")
	} else if message.signatures == nil {
		return nil, nil, errors.New("nil sigs")
	} else if len(message.signatures) < 1 {
		return nil, nil, errors.New("no sig to hash")
	} else if message.signatures[0].headers == nil {
		return nil, nil, errors.New("nil sig headers")
	} else if message.signatures[0].headers.protected == nil {
		return nil, nil, errors.New("nil sig headers.protected")
	}

	// TODO: check if provided privateKey verify alg, bitsize, and supported key_ops in protected
	if !(message.signatures[0].headers.protected["alg"] == "ES256" || message.signatures[0].headers.protected[uint64(1)] == int64(-7)) {
		return nil, nil, errors.New("alg not implemented.")
	}

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
		external,
		message.payload,
	}

	// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
	//     byte string, using the encoding described in Section 14.
	ToBeSigned, err = CBOREncode(sig_structure)
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("CBOREncode error encoding sig_structure: %s", err))
	}

	var hash crypto.Hash

	// ES256
	// expectedBitSize := 256
	hash = crypto.SHA256

	hasher := hash.New()
	_, _ = hasher.Write(ToBeSigned)  // Write() on hash never fails
	hashed = hasher.Sum(nil)
	return hashed, ToBeSigned, nil
}


// TODO: rewrite as Signer(kid, alg key config).Sign(payload, ext_data)
//
// Signing and Verification Process
// https://tools.ietf.org/html/rfc8152#section-4.4
func Sign(message *COSESignMessage, key *ecdsa.PrivateKey, randReader io.Reader, external []byte) (result *COSESignMessage, err error, ToBeSigned []byte) {
	hashed, ToBeSigned, err := hashSigStructure(message, &key.PublicKey, external)
	if err != nil {
		return nil, err, nil
	}

	// 3.  Call the signature creation algorithm passing in K (the key to
	//     sign with), alg (the algorithm to sign with), and ToBeSigned (the
	//     value to sign).

	// https://tools.ietf.org/html/rfc8152#section-8.1
	r, s, err := ecdsa.Sign(randReader, key, hashed)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("ecdsa.Sign error %s", err)), nil
	}
	// assert r and s are the same length will be the same length
	// as the length of the key used for the signature process
	// fmt.Println(fmt.Printf("\nr: %+v\ns: %+v\n %+x", r, s, hashed))

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

	// fmt.Println(fmt.Printf("\nr: %+x\ns: %+x\n", rBytes, sBytes))

	n := keyBytes
	sig := make([]byte, 0)
	sig = append(sig, I2OSP(r, n)...)
	sig = append(sig, I2OSP(s, n)...)

	// 4.  Place the resulting signature value in the 'signature' field of the array.
	message.signatures[0].signature = sig

	// fmt.Println(fmt.Printf("%+v", message))
	return message, nil, ToBeSigned
}

func Verify(message *COSESignMessage, publicKey *ecdsa.PublicKey, external []byte) (ok bool, err error) {
	hashed, _, err := hashSigStructure(message, publicKey, external)
	if err != nil {
		return false, err
	}

	// ES256 / sha256
	keySize := 32

	// r and s from sig
	signature := message.signatures[0].signature
	if len(signature) != 2 * keySize {
		return false, errors.New(fmt.Sprintf("invalid signature length: %d", len(signature)))
	}

	r := big.NewInt(0).SetBytes(signature[:keySize])
	s := big.NewInt(0).SetBytes(signature[keySize:])

	ok = ecdsa.Verify(publicKey, hashed, r, s)
	if ok {
		return ok, nil
	} else {
		return ok, errors.New("verification failed")
	}
}
