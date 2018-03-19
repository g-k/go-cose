
package cose

import (
	"errors"
	"crypto/ecdsa"
	"fmt"
	"io"
)

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
func (s *COSESignature) SetHeaders(h *COSEHeaders) {
	s.headers = h
}
func (s *COSESignature) Decode(o interface {}) {
	array, ok := o.([]interface {})
	if !ok {
		panic(fmt.Sprintf("error decoding sigArray; got %T", array))
	}
	if len(array) != 3 {
		panic(fmt.Sprintf("can only decode COSESignature with 3 items; got %d", len(array)))
	}

	err := s.headers.DecodeProtected(array[0])
	if err != nil {
		panic(fmt.Sprintf("error decoding protected header bytes; got %s", err))
	}
	err = s.headers.DecodeUnprotected(array[1])
	if err != nil {
		panic(fmt.Sprintf("error decoding unprotected header map; got %s", err))
	}

	signature, ok := array[2].([]byte)
	if !ok {
		panic(fmt.Sprintf("unable to decode COSE signature expecting decode from interface{}; got %T", array[2]))
	}
	s.signature = signature
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
func (m *COSESignMessage) SigStructure(external []byte, signature *COSESignature) (ToBeSigned []byte, err error) {
	ToBeSigned, err = buildAndCBOREncodeSigStructure(
		m.headers.EncodeProtected(),
		signature.headers.EncodeProtected(),
		external,
		m.payload)
	return
}
func (m *COSESignMessage) SignatureDigest(external []byte, signature *COSESignature) (digest []byte, err error) {
	ToBeSigned, err := m.SigStructure(external, signature)
	if err != nil {
		return nil, err
	}

	alg, err := getAlg(signature.headers)
	if err != nil {
		return nil, err
	}
	_, hash, err := getExpectedArgsForAlg(alg)
	if err != nil {
		return nil, err
	}

	digest = hashSigStructure(ToBeSigned, hash)

	return digest, err
}


// Signing and Verification Process
// https://tools.ietf.org/html/rfc8152#section-4.4

// Sign - signs a COSESignMessage in place populating signatures[].signature
func (m *COSESignMessage) Sign(rand io.Reader, external []byte, opts SignOpts) (err error) {
	if m.signatures == nil {
		return errors.New("nil sigs")
	} else if len(m.signatures) < 1 {
		return errors.New("No signatures to sign the message. Use AddSignature to add them.")
	}

	for i, signature := range m.signatures {
		if signature.headers == nil {
			return errors.New("nil sig headers")
		} else if signature.headers.protected == nil {
			return errors.New("nil sig headers.protected")
		}
		// else if signature.signature != nil || len(signature.signature) > 0 {
		// 	return errors.New(fmt.Sprintf("message already has a signature at %d %s", i, signature.signature))
		// }
		// TODO: check if provided privateKey verify alg, bitsize, and supported key_ops in protected

		// 1.  Create a Sig_structure and populate it with the appropriate fields.
		//
		// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
		//     byte string, using the encoding described in Section 14.
		ToBeSigned, err := buildAndCBOREncodeSigStructure(
			m.headers.EncodeProtected(),
			signature.headers.EncodeProtected(),
			external,
			m.payload)
		if err != nil {
			return err
		}

		alg, err := getAlg(signature.headers)
		if err != nil {
			return err
		}
		_, hash, err := getExpectedArgsForAlg(alg)
		if err != nil {
			return err
		}
		opts.HashFunc = hash

		digest := hashSigStructure(ToBeSigned, hash)

		signer, err := opts.GetSigner(i, signature)
		if err != nil {
			return errors.New(fmt.Sprintf("Error finding a Signer for signature %d", i))
		}

		// 3.  Call the signature creation algorithm passing in K (the key to
		//     sign with), alg (the algorithm to sign with), and ToBeSigned (the
		//     value to sign).
		signature, err := signer.Sign(rand, digest, opts)
		if err != nil {
			return err
		}

		// 4.  Place the resulting signature value in the 'signature' field of the array.
		m.signatures[i].signature = signature
	}
	return nil
}
// Verify - verifies all signatures on the COSESignMessage
func (m *COSESignMessage) Verify(external []byte, opts *VerifyOpts) (err error) {
	if m.signatures == nil {
		return nil  // Nothing to check
	}
	// TODO: take a func for a signature kid that returns a key or not?

	for i, signature := range m.signatures {
		if signature.headers == nil {
			return errors.New("nil sig headers")
		} else if signature.headers.protected == nil {
			return errors.New("nil sig headers.protected")
		} else if signature.signature == nil || len(signature.signature) < 1 {
			return errors.New(fmt.Sprintf("message missing a signature at %d %+v", i, signature))
		}
		// TODO: check if provided privateKey verify alg, bitsize, and supported key_ops in protected

		// 1.  Create a Sig_structure and populate it with the appropriate fields.
		//
		// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
		//     byte string, using the encoding described in Section 14.
		ToBeSigned, err := buildAndCBOREncodeSigStructure(
			m.headers.EncodeProtected(),
			signature.headers.EncodeProtected(),
			external,
			m.payload)
		if err != nil {
			return err
		}

		alg, err := getAlg(signature.headers)
		if err != nil {
			return err
		}
		expectedKeyBitSize, hash, err := getExpectedArgsForAlg(alg)
		if err != nil {
			return err
		}

		digest := hashSigStructure(ToBeSigned, hash)

		verifier, err := opts.GetVerifier(i, signature)
		if err != nil {
			return errors.New(fmt.Sprintf("Error finding a Verifier for signature %d %+v", i, signature))
		}
		if ecdsaKey, ok := verifier.publicKey.(*ecdsa.PublicKey); ok {
			curveBits := ecdsaKey.Curve.Params().BitSize
			if expectedKeyBitSize != curveBits {
				return fmt.Errorf("for signature %d expected %d bit key, got %d bits instead", i, expectedKeyBitSize, curveBits)
			}
		}

		// 3.  Call the signature creation algorithm passing in K (the key to
		//     sign with), alg (the algorithm to sign with), and ToBeSigned (the
		//     value to sign).
		err = verifier.Verify(digest, signature.signature)
		if err != nil {
			return err
		}
	}
	return
}
