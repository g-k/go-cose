package cose

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
)

// Signature represents a COSE signature with CDDL fragment:
//
// COSE_Signature =  [
//        Headers,
//        signature : bstr
// ]
//
// https://tools.ietf.org/html/rfc8152#section-4.1
type Signature struct {
	headers   *Headers
	signature []byte
}

// NewSignature returns a new COSE Signature with empty headers and
// nil signature bytes
func NewSignature() (s *Signature) {
	return &Signature{
		headers: &Headers{
			protected:   map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		signature: nil,
	}
}

// Decode updates the signature inplace from its COSE serialization
// (see the docs for Signature)
func (s *Signature) Decode(o interface{}) {
	array, ok := o.([]interface{})
	if !ok {
		panic(fmt.Sprintf("error decoding sigArray; got %T", array))
	}
	if len(array) != 3 {
		panic(fmt.Sprintf("can only decode Signature with 3 items; got %d", len(array)))
	}

	err := s.headers.Decode(array[0:2])
	if err != nil {
		panic(fmt.Sprintf("error decoding signature header: %+v", err))
	}

	signature, ok := array[2].([]byte)
	if !ok {
		panic(fmt.Sprintf("unable to decode COSE signature expecting decode from interface{}; got %T", array[2]))
	}
	s.signature = signature
}

// SignMessage represents a COSESignMessage with CDDL fragment:
//
// COSE_Sign = [
//        Headers,
//        payload : bstr / nil,
//        signatures : [+ COSE_Signature]
// ]
//
// https://tools.ietf.org/html/rfc8152#section-4.1
type SignMessage struct {
	headers    *Headers
	payload    []byte
	signatures []Signature
}

// NewSignMessage takes a []byte payload and returns a new SignMessage
// with empty headers and signatures
func NewSignMessage(payload []byte) (msg SignMessage) {
	msg = SignMessage{
		headers: &Headers{
			protected:   map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		payload:    payload,
		signatures: []Signature{},
	}
	return msg
}

// AddSignature adds a signature to the message signatures
func (m *SignMessage) AddSignature(s *Signature) {
	if m.signatures == nil {
		m.signatures = []Signature{}
	}
	m.signatures = append(m.signatures, *s)
}

// SigStructure returns the byte slice to be signed for tests and debugging
func (m *SignMessage) SigStructure(external []byte, signature *Signature) (ToBeSigned []byte, err error) {
	ToBeSigned, err = buildAndMarshalSigStructure(
		m.headers.EncodeProtected(),
		signature.headers.EncodeProtected(),
		external,
		m.payload)
	return
}

// SignatureDigest takes a slice of extra external byte (can be
// []byte) and a signature and returns the SigStructure
// (i.e. ToBeSigned) hashed using the algorithm from the signature
// parameter
// TODO: check that signature is in SignMessage?
func (m *SignMessage) SignatureDigest(external []byte, signature *Signature) (digest []byte, err error) {
	ToBeSigned, err := m.SigStructure(external, signature)
	if err != nil {
		return nil, err
	}

	alg, err := getAlg(signature.headers)
	if err != nil {
		return nil, err
	}

	digest = hashSigStructure(ToBeSigned, alg.HashFunc)

	return digest, err
}

// Signing and Verification Process
// https://tools.ietf.org/html/rfc8152#section-4.4

// Sign signs a SignMessage populating signatures[].signature in place
func (m *SignMessage) Sign(rand io.Reader, external []byte, opts SignOpts) (err error) {
	if m.signatures == nil {
		return errors.New("SignMessage.signatures is nil. Use AddSignature to add one")
	} else if len(m.signatures) < 1 {
		return errors.New("No signatures to sign the message. Use AddSignature to add them")
	}

	for i, signature := range m.signatures {
		if signature.headers == nil {
			return errors.New("Signature.headers is nil")
		} else if signature.headers.protected == nil {
			return errors.New("Signature.headers.protected is nil")
		} else if signature.signature != nil || len(signature.signature) > 0 {
			return fmt.Errorf("SignMessage signature %d already has signature bytes (at .signature)", i)
		}
		// TODO: check if provided privateKey verify alg, bitsize, and supported key_ops in protected

		// 1.  Create a Sig_structure and populate it with the appropriate fields.
		//
		// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
		//     byte string, using the encoding described in Section 14.
		ToBeSigned, err := buildAndMarshalSigStructure(
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
		opts.HashFunc = alg.HashFunc

		digest := hashSigStructure(ToBeSigned, alg.HashFunc)

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

// Verify verifies all signatures on the SignMessage
func (m *SignMessage) Verify(external []byte, opts *VerifyOpts) (err error) {
	if m.signatures == nil {
		return nil // Nothing to check
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
		ToBeSigned, err := buildAndMarshalSigStructure(
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
		expectedKeyBitSize, err := getExpectedArgsForAlg(alg)
		if err != nil {
			return err
		}

		digest := hashSigStructure(ToBeSigned, alg.HashFunc)

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
