
package cose

import (
	"errors"
	"bytes"
	"math/big"
	"crypto"
	"crypto/rsa"
	"crypto/ecdsa"
	"fmt"
	// "log"
	"io"
	generated "github.com/g-k/go-cose/generated"
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


func getAlg(h *COSEHeaders) (alg *generated.COSEAlgorithm, err error) {
	if tmp, ok := h.protected["alg"]; ok {
		if algName, ok := tmp.(string); ok {
			// fmt.Println(fmt.Sprintf("get by alg name %+v", algName))
			alg, err = GetAlgByName(algName)
			if err != nil {
				return nil, err
			} else {
				return alg, nil
			}
		}
	} else if tmp, ok := h.protected[uint64(1)]; ok {
		// fmt.Println(fmt.Sprintf("get by value? %T", tmp))
		if algValue, ok := tmp.(int64); ok {
			// fmt.Println(fmt.Sprintf("get by value %+v", algValue))
			alg, err = GetAlgByValue(algValue)
			if err != nil {
				return nil, err
			} else {
				return alg, nil
			}

		}
	} else if tmp, ok := h.protected[int(1)]; ok {
		// fmt.Println(fmt.Sprintf("get by value int? %T", tmp))
		if algValue, ok := tmp.(int); ok {
			// fmt.Println(fmt.Sprintf("get by value int? %+v", algValue))
			alg, err = GetAlgByValue(int64(algValue))
			if err != nil {
				return nil, err
			} else {
				return alg, nil
			}

		}
	}
	// ai, _ := h.protected[uint64(1)].(int)
	// fmt.Println(fmt.Sprintf("getAlg else %+v %+v", h.protected, ai))
	return nil, errors.New("Error fetching alg.")
}

func hashSigStructure(
	message *COSESignMessage,
	key crypto.PublicKey,
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
	alg, err := getAlg(message.signatures[0].headers)
	if err != nil {
		return nil, nil, err
	}

	// TODO: check if provided privateKey verify alg, bitsize, and supported key_ops in protected

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
		return nil, ToBeSigned, errors.New(fmt.Sprintf("CBOREncode error encoding sig_structure: %s", err))
	}

	var hash crypto.Hash

	if alg.Value == GetAlgByNameOrPanic("ES256").Value {
		hash = crypto.SHA256
		// expectedBitSize := 256
	} else if alg.Value == GetAlgByNameOrPanic("ES384").Value {
		hash = crypto.SHA384
	} else if alg.Value == GetAlgByNameOrPanic("ES512").Value {
		hash = crypto.SHA512
	} else if alg.Value == GetAlgByNameOrPanic("PS256").Value {
		hash = crypto.SHA256
	} else {
		return nil, nil, errors.New("alg not implemented.")
	}

	hasher := hash.New()
	_, _ = hasher.Write(ToBeSigned)  // Write() on hash never fails
	hashed = hasher.Sum(nil)
	return hashed, ToBeSigned, nil
}


// TODO: rewrite as Signer(kid, alg key config).NewSignData(payload, ext_data)
//
// Signing and Verification Process
// https://tools.ietf.org/html/rfc8152#section-4.4
func Sign(message *COSESignMessage, privateKey crypto.PrivateKey, randReader io.Reader, external []byte) (result *COSESignMessage, err error, ToBeSigned []byte) {
	// TODO: sign non-first slots
	// if message.signatures[0].signature != nil || len(message.signatures[0].signature) > 0 {
	// 	return nil, errors.New(fmt.Sprintf("message already has a signature %s", message.signatures[0].signature)), ToBeSigned
	// }

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		hashed, ToBeSigned, err := hashSigStructure(message, &key.PublicKey, external)
		if err != nil {
			return nil, err, ToBeSigned
		}

		// TODO: pass signature alg or pick hash based on protected alg value
		sig, err := rsa.SignPSS(randReader, key, crypto.SHA256, hashed, nil)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("rsa SignPSS error %s", err)), ToBeSigned
		}

		// 4.  Place the resulting signature value in the 'signature' field of the array.
		message.signatures[0].signature = sig

		return message, nil, ToBeSigned
	case *ecdsa.PrivateKey:
		hashed, ToBeSigned, err := hashSigStructure(message, &key.PublicKey, external)
		if err != nil {
			return nil, err, ToBeSigned
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

		return message, nil, ToBeSigned
	default:
		return nil, errors.New("Unrecognized private key type"), nil
	}
}

// Verify
// TODO: verify should return err and not ok
func Verify(message *COSESignMessage, publicKey crypto.PublicKey, external []byte) (ok bool, err error) {
	// fmt.Println(fmt.Sprintf("Verify Crv: %+v", publicKey.Curve.Params().BitSize))
	// fmt.Println(fmt.Sprintf("pre Hash msg: %+v", message))

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		// return false, errors.New("Unrecognized rsa publicKey type.")
		hashed, _, err := hashSigStructure(message, key, external)
		// fmt.Println(fmt.Sprintf("Hash err: %+v %+v", err, message))
		if err != nil {
			return false, err
		}

		// keySize := key.Curve.Params().BitSize / 8
		signature := message.signatures[0].signature
		// if len(signature) != 2 * keySize {
		// 	return false, errors.New(fmt.Sprintf("invalid signature length: %d", len(signature)))
		// }

		// TODO: pass signature alg or pick hash based on protected alg value
		err = rsa.VerifyPSS(key, crypto.SHA256, hashed, signature, nil)
		if err != nil {
			// todo: wrap err?
			return false, errors.New(fmt.Sprintf("verification failed %s", err))
		} else {
			return true, nil
		}
	case *ecdsa.PublicKey:
		hashed, _, err := hashSigStructure(message, key, external)
		// fmt.Println(fmt.Sprintf("Hash err: %+v %+v", err, message))
		if err != nil {
			return false, err
		}

		keySize := key.Curve.Params().BitSize / 8

		// r and s from sig
		signature := message.signatures[0].signature
		if len(signature) != 2 * keySize {
			return false, errors.New(fmt.Sprintf("invalid signature length: %d", len(signature)))
		}

		r := big.NewInt(0).SetBytes(signature[:keySize])
		s := big.NewInt(0).SetBytes(signature[keySize:])

		ok = ecdsa.Verify(key, hashed, r, s)
		if ok {
			return ok, nil
		} else {
			return ok, errors.New("verification failed")
		}
	default:
		return false, errors.New("Unrecognized publicKey type.")
	}
}
