package cose

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestSignErrors(t *testing.T) {
	assert := assert.New(t)

	randReader := rand.New(rand.NewSource(int64(0)))

	msg := NewSignMessage([]byte("payload to sign"))

	ecdsaPrivateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     FromBase64Int("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
			Y:     FromBase64Int("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
		},
		D: FromBase64Int("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
	}

	dsaPrivateKey := dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: FromBase64Int("A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF"),
				Q: FromBase64Int("E1D3391245933D68A0714ED34BBCB7A1F422B9C1"),
				G: FromBase64Int("634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA"),
			},
			Y: FromBase64Int("32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2"),
		},
		X: FromBase64Int("5078D4D29795CBE76D3AACFE48C9AF0BCDBEE91A"),
	}

	signer, err := NewSigner(&ecdsaPrivateKey)
	assert.Nil(err, fmt.Sprintf("Error creating signer %s", err))

	opts := SignOpts{
		HashFunc: crypto.SHA256,
		GetSigner: func(index int, signature Signature) (Signer, error) {
			return *signer, NoSignerFoundErr
		},
	}

	sig := NewSignature()
	sig.headers.protected[algTag] = -41 // RSAES-OAEP w/ SHA-256 from [RFC8230]
	sig.headers.protected[kidTag] = 1

	msg.signatures = []Signature{}
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(NoSignaturesErr, err)

	msg.signatures = nil
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(NilSignaturesErr, err)

	// check that it creates the signatures array from nil
	msg.AddSignature(sig)
	assert.Equal(len(msg.signatures), 1)

	msg.signatures[0].headers = nil
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(NilSigHeaderErr, err)

	msg.signatures = nil
	msg.AddSignature(sig)
	msg.signatures[0].headers.protected = nil
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(NilSigProtectedHeadersErr, err)

	msg.signatures = nil
	sig.headers.protected = map[interface{}]interface{}{}
	sig.headers.protected[algTag] = -41 // RSAES-OAEP w/ SHA-256 from [RFC8230]
	sig.headers.protected[kidTag] = 1
	sig.signature = []byte("already signed")

	msg.AddSignature(sig)
	assert.Equal(len(msg.signatures), 1)
	assert.NotNil(msg.signatures[0].headers)
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(errors.New("SignMessage signature 0 already has signature bytes (at .signature)"), err)

	msg.signatures[0].signature = nil
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(UnavailableHashFuncErr, err)

	msg.signatures[0].headers.protected[algTag] = -7 // ECDSA w/ SHA-256 from [RFC8152]
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(errors.New("Error finding a Signer for signature 0"), err)

	signer.privateKey = dsaPrivateKey

	opts.GetSigner = func(index int, signature Signature) (Signer, error) {
		return *signer, nil
	}
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(UnknownPrivateKeyTypeErr, err)

	msg.signatures[0].headers.protected[algTag] = -9000
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(errors.New("Algorithm with value -9000 not found"), err)

	delete(msg.signatures[0].headers.protected, algTag)
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(AlgNotFoundErr, err)
}

func TestVerifyErrors(t *testing.T) {
	assert := assert.New(t)

	// randReader := rand.New(rand.NewSource(int64(0)))
	msg := NewSignMessage([]byte("payload to sign"))

	ecdsaPrivateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     FromBase64Int("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
			Y:     FromBase64Int("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
		},
		D: FromBase64Int("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
	}

	sig := NewSignature()
	sig.headers.protected[algTag] = -41 // RSAES-OAEP w/ SHA-256 from [RFC8230]
	sig.headers.protected[kidTag] = 1

	signer, err := NewSigner(&ecdsaPrivateKey)
	assert.Nil(err, "Error creating signer")

	verifier := signer.Verifier(GetAlgByNameOrPanic("ES256"))
	assert.Nil(err, "Error creating verifier")

	opts := VerifyOpts{
		GetVerifier: func(index int, signature Signature) (Verifier, error) {
			return *verifier, nil
		},
	}
	payload := []byte("")

	msg.signatures = []Signature{}
	assert.Nil(msg.Verify(payload, &opts))

	msg.signatures = nil
	assert.Nil(msg.Verify(payload, &opts))

	msg.AddSignature(sig)
	msg.signatures[0].headers.protected = nil
	assert.Equal(NilSigProtectedHeadersErr, msg.Verify(payload, &opts))

	msg.signatures[0].headers = nil
	assert.Equal(NilSigHeaderErr, msg.Verify(payload, &opts))

	sig = NewSignature()
	sig.headers.protected[algTag] = -41 // RSAES-OAEP w/ SHA-256 from [RFC8230]
	sig.headers.protected[kidTag] = 1
	msg.signatures[0] = *sig
	assert.Equal(errors.New("SignMessage signature 0 missing signature bytes (at .signature) to verify"), msg.Verify(payload, &opts))

	msg.signatures[0].headers.protected[algTag] = -41 // RSAES-OAEP w/ SHA-256 from [RFC8230]
	msg.signatures[0].headers.protected[kidTag] = 1
	msg.signatures[0].signature = []byte("already signed")
	assert.Equal(UnavailableHashFuncErr, msg.Verify(payload, &opts))

	msg.signatures[0].headers.protected[algTag] = -7 // ECDSA w/ SHA-256 from [RFC8152]
	assert.Equal(errors.New("Error finding a Verifier for signature 0"), msg.Verify(payload, &VerifyOpts{
		GetVerifier: func(index int, signature Signature) (Verifier, error) {
			return *verifier, NoVerifierFoundErr
		},
	}))

	verifier = &Verifier{
		publicKey: ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     FromBase64Int("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
			Y:     FromBase64Int("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
		},
		alg: GetAlgByNameOrPanic("ES256"),
	}
	assert.Equal(errors.New("Error verifying signature 0 expected 256 bit key, got 384 bits instead"), msg.Verify(payload, &opts))

	verifier = &Verifier{
		publicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     FromBase64Int("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
			Y:     FromBase64Int("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
		},
		alg: GetAlgByNameOrPanic("ES256"),
	}
	assert.Equal(errors.New("invalid signature length: 14"), msg.Verify(payload, &opts))
}
