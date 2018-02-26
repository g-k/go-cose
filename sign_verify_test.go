
package cose

import (
	"bytes"
	"strings"
	// "crypto"
	// "math/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"log"
	"testing"
	"encoding/hex"
	"github.com/g-k/go-cose/test"
	"github.com/stretchr/testify/assert"
	// codec "github.com/ugorji/go/codec"
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

	msgBytes, hexDecodeErr := hex.DecodeString(example.Output.Cbor)
	assert.Nil(hexDecodeErr, "Error decoding example hex")

	decoded, err := CBORDecode(msgBytes)
	assert.Nil(err, "Error decoding example CBOR")

	msg, ok := decoded.(COSESignMessage)
	assert.True(ok, "Error casting example CBOR as COSESignMessage")

	fmt.Println(fmt.Printf("Verifying sig[0]: %x %d", msg.signatures[0].signature, len(msg.signatures[0].signature) / 8))

	ok, err = Verify(&msg, &privateKey.PublicKey)
	assert.Nil(err)
	assert.True(ok)
}


func TestSignExample(t *testing.T) {
	example := test.LoadExample("./test/cose-wg-examples/sign-tests/sign-pass-01.json")
	assert := assert.New(t)

	msg := COSESignMessage{
		headers: &COSEHeaders{
			protected: map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		payload: []byte(example.Input.Plaintext),
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

	// TODO: func to convert example to sign msg
	// ignore example.Input.Sign.Protected.Ctyp

	signerInput := example.Input.Sign.Signers[0]
	msg.signatures[0].headers.protected["alg"] = signerInput.Protected.Alg
	msg.signatures[0].headers.unprotected["kid"] = signerInput.Unprotected.Kid

	log.Println(fmt.Printf("%+v", msg))

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

	// TODO: preprocess input to have a reasonable format
	_, err, ToBeSigned := Sign(&msg, &privateKey, randReader)
	assert.Nil(err)

	toSign := strings.ToUpper(hex.EncodeToString(ToBeSigned))
	// log.Println(fmt.Printf("ToBeSigned %+v", ToBeSigned))
	assert.Equal(example.Intermediates.Signers[0].ToBeSignHex, toSign, "sig_signature wrong")

	// pull signature from the example
	// exampleDecodedBytes, hexDecodeErr := hex.DecodeString(example.Output.Cbor)
	// assert.Nil(hexDecodeErr, "Error decoding example hex")

	// var dec *codec.Decoder = codec.NewDecoderBytes(exampleDecodedBytes, GetCOSEHandle())
	// var exampleDecodedCBOR = make([]interface{}, 4)
	// {
	// 	protectedHeaders []byte
	// 	unprotectedHeaders []byte
	// 	payload []byte
	// 	signatures map[string]interface{}
	// }
	// cborDecodeErr := dec.Decode(exampleDecodedCBOR)
	// assert.Nil(cborDecodeErr, "Error decoding example cbor")

	// log.Println(fmt.Printf("exampledDCOR %+v", exampleDecodedCBOR))

	// assert.Equal(exampleDecodedCBOR, output.signatures[0].signature, "signature wrong")

	// signed := strings.ToUpper(hex.EncodeToString(CBOREncode(output)))
	// log.Println(fmt.Printf("signed %+v", signed))

	// assert.Equal(example.Output.Cbor, signed, "CBOR encoded message wrong")

	// Verify our signature (round trip)
	// ok, err := Verify(output, &privateKey.PublicKey)
	// assert.Nil(err)
	// assert.True(ok)

	// Verify the example signature
	// msgBytes, hexDecodeErr := hex.DecodeString(example.Output.Cbor)
	// assert.Nil(hexDecodeErr, "Error decoding example hex")

	// decoded, err := CBORDecode(msgBytes)
	// assert.Nil(err, "Error decoding example CBOR")

	// msg, ok := decoded.(COSESignMessage)
	// assert.True(ok, "Error casting example CBOR as COSESignMessage")

	// ok, err = Verify(&msg, &privateKey.PublicKey)
	// assert.Nil(err)
	// assert.True(ok)

	// check for matching cbor
	// assert.Equal(output, example.Output.Cbor)
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
