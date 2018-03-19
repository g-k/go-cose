
package cose

import (
	"errors"
	"crypto/ecdsa"
	"fmt"
	"io"
)

// Signature https://tools.ietf.org/html/rfc8152#section-4.1
type Signature struct {
	headers *Headers
	signature []byte
}
// NewSignature -
func NewSignature() (s *Signature) {
	return &Signature{
		headers: &Headers{
			protected: map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		signature: nil,
	}
}
// SetHeaders -
func (s *Signature) SetHeaders(h *Headers) {
	s.headers = h
}
// Decode -
func (s *Signature) Decode(o interface {}) {
	array, ok := o.([]interface {})
	if !ok {
		panic(fmt.Sprintf("error decoding sigArray; got %T", array))
	}
	if len(array) != 3 {
		panic(fmt.Sprintf("can only decode Signature with 3 items; got %d", len(array)))
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


// SignMessage https://tools.ietf.org/html/rfc8152#section-4.1
type SignMessage struct {
	headers *Headers
	payload []byte
	signatures []Signature
}
// NewSignMessage -
func NewSignMessage(payload []byte) (msg SignMessage) {
	msg = SignMessage{
		headers: &Headers{
			protected: map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		payload: payload,
		signatures: []Signature{},
	}
	return msg
}
// AddSignature -
func (m *SignMessage) AddSignature(s *Signature) {
	m.signatures = append(m.signatures, *s)
}
// SetHeaders -
func (m *SignMessage) SetHeaders(h *Headers) {
	m.headers = h
}
// SigStructure -
func (m *SignMessage) SigStructure(external []byte, signature *Signature) (ToBeSigned []byte, err error) {
	ToBeSigned, err = buildAndCBOREncodeSigStructure(
		m.headers.EncodeProtected(),
		signature.headers.EncodeProtected(),
		external,
		m.payload)
	return
}
// SignatureDigest -
func (m *SignMessage) SignatureDigest(external []byte, signature *Signature) (digest []byte, err error) {
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

// Sign - signs a SignMessage populating signatures[].signature in place
func (m *SignMessage) Sign(rand io.Reader, external []byte, opts SignOpts) (err error) {
	if m.signatures == nil {
		return errors.New("nil sigs")
	} else if len(m.signatures) < 1 {
		return errors.New("No signatures to sign the message. Use AddSignature to add them")
	}

	for i, signature := range m.signatures {
		if signature.headers == nil {
			return errors.New("nil sig headers")
		} else if signature.headers.protected == nil {
			return errors.New("nil sig headers.protected")
		}
		// else if signature.signature != nil || len(signature.signature) > 0 {
		// 	return fmt.Errorf("message already has a signature at %d %s", i, signature.signature)
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
			return fmt.Errorf("Error finding a Signer for signature %d", i)
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
// Verify - verifies all signatures on the SignMessage
func (m *SignMessage) Verify(external []byte, opts *VerifyOpts) (err error) {
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
			return fmt.Errorf("message missing a signature at %d %+v", i, signature)
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
			return fmt.Errorf("Error finding a Verifier for signature %d %+v", i, signature)
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
