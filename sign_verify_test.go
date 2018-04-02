package cose

import (
	"fmt"
	"math/rand"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"github.com/mozilla-services/go-cose/util"
	"github.com/stretchr/testify/assert"
	"testing"
)


func TestSignErrors(t *testing.T) {
	assert := assert.New(t)

	randReader := rand.New(rand.NewSource(int64(0)))

	msg := NewSignMessage([]byte("paylod to sign"))

	privateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X: util.FromBase64Int("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
			Y: util.FromBase64Int("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
		},
		D: util.FromBase64Int("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
	}

	signer, err := NewSigner(&privateKey)
	assert.Nil(err, fmt.Sprintf("Error creating signer %s", err))

	opts := SignOpts{
		HashFunc: crypto.SHA256,
		GetSigner: func(index int, signature Signature) (Signer, error) {
			return *signer, errors.New("No signer found.")
		},
	}

	sig := NewSignature()
	sig.headers.protected[algTag] = -41  // RSAES-OAEP w/ SHA-256 from [RFC8230]
	sig.headers.protected[kidTag] = 1


	msg.signatures = []Signature{}
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(errors.New("No signatures to sign the message. Use AddSignature to add them"), err)

	msg.signatures = nil
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(errors.New("SignMessage.signatures is nil. Use AddSignature to add one"), err)

	// check that it creates the signatures array from nil
	msg.AddSignature(sig)
	assert.Equal(len(msg.signatures), 1)

	msg.signatures[0].headers = nil
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(errors.New("Signature.headers is nil"), err)

	msg.signatures = nil
	msg.AddSignature(sig)
	msg.signatures[0].headers.protected = nil
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(errors.New("Signature.headers.protected is nil"), err)

	msg.signatures = nil
	sig.headers.protected = map[interface{}]interface{}{}
	sig.headers.protected[algTag] = -41  // RSAES-OAEP w/ SHA-256 from [RFC8230]
	sig.headers.protected[kidTag] = 1
	sig.signature = []byte("already signed")

	msg.AddSignature(sig)
	assert.Equal(len(msg.signatures), 1)
	assert.NotNil(msg.signatures[0].headers)
	err = msg.Sign(randReader, []byte(""), opts)
	assert.Equal(errors.New("SignMessage signature 0 already has signature bytes (at .signature)"), err)
}
