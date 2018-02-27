
package cose

import (
	"bytes"
	"strings"
	// "crypto"
	// "math/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
	// "fmt"
	"testing"
	"encoding/hex"
	"github.com/g-k/go-cose/test"
	"github.com/stretchr/testify/assert"
)

func TestVerifyExample(t *testing.T) {
	assert := assert.New(t)
	example := test.LoadExample("./test/cose-wg-examples/sign-tests/sign-pass-01.json")

	signerInput := example.Input.Sign.Signers[0]

	privateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X: test.FromBase64Int(signerInput.Key.X),
			Y: test.FromBase64Int(signerInput.Key.Y),
		},
		D: test.FromBase64Int(signerInput.Key.D),
	}

	msgBytes := test.HexToBytesOrDie(example.Output.Cbor)

	decoded, err := CBORDecode(msgBytes)
	assert.Nil(err, "Error decoding example CBOR")

	msg, ok := decoded.(COSESignMessage)
	assert.True(ok, "Error casting example CBOR as COSESignMessage")

	ok, err = Verify(&msg, &privateKey.PublicKey)
	assert.Nil(err)
	assert.True(ok)
}


func TestSignExample(t *testing.T) {
	example := test.LoadExample("./test/cose-wg-examples/sign-tests/sign-pass-01.json")
	// NB: we ignore example.Input.Sign.Protected.Ctyp

	assert := assert.New(t)

	msg := NewCOSESignMessage([]byte(example.Input.Plaintext))

	// TODO: extract to func to convert example to sign msg
	signerInput := example.Input.Sign.Signers[0]

	msgSig := NewCOSESignature()
	msgSig.headers.protected["alg"] = signerInput.Protected.Alg
	msgSig.headers.unprotected["kid"] = signerInput.Unprotected.Kid

	msg.AddSignature(msgSig)
	// fmt.Println(fmt.Printf("TestSignExample %+v %+v", msgSig.headers.unprotected, msg.signatures[0].headers))

	privateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X: test.FromBase64Int(signerInput.Key.X),
			Y: test.FromBase64Int(signerInput.Key.Y),
		},
		D: test.FromBase64Int(signerInput.Key.D),
	}

	randReader := bytes.NewReader([]byte(example.Input.RngDescription))
	// randReader := rand.New(rand.NewSource(example.Input.RngDescription))

	output, err, ToBeSigned := Sign(&msg, &privateKey, randReader)
	assert.Nil(err)

	toSign := strings.ToUpper(hex.EncodeToString(ToBeSigned))
	// log.Println(fmt.Printf("ToBeSigned %+v", ToBeSigned))
	assert.Equal(example.Intermediates.Signers[0].ToBeSignHex, toSign, "sig_signature wrong")

	// check cbor matches
	// signed := strings.ToUpper(hex.EncodeToString(CBOREncode(output)))
	// assert.Equal(example.Output.Cbor, signed, "CBOR encoded message wrong")

	// Verify our signature (round trip)
	ok, err := Verify(output, &privateKey.PublicKey)
	assert.Nil(err)
	assert.True(ok)
}

	// for _, example := range test.LoadExamples("./test/cose-wg-examples/sign-tests") {
	// 	assert := assert.New(t)

	// 	if (example.Title != "sign-pass-01: Redo protected") {
	// 		continue
	// 	}

	// 	// if (example.Fail) {
	// 	// 	// check for error
	// 	// } else {
	// 	// }
	// }
