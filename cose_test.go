
package cose

import (
	// "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"log"
	"testing"
	"encoding/hex"
	"github.com/g-k/go-cose/test"
	"github.com/stretchr/testify/assert"
	"strings"
)


// var CBOREncodeTestCases = []struct {
// 	name string
// 	input interface{}
// 	output interface{}
// }{
// 	{
// 		"empty bstr",
// 		[]byte(""),
// 		[]byte("\x40"),
// 	},
// 	{
// 		"alg header",
// 		COSEHeaders{
// 			protected: map[interface{}]interface{}{"alg": "ES256"},
// 			unprotected: map[interface{}]interface{}{},
// 		},
// 		// 0x43 for bytes h'A10126'
// 		// decoding h'A10126' gives:
// 		//     A1    # map(1)
// 		//       01 # unsigned(1)
// 		//       26 # negative(6)
// 		[]byte("\x43\xA1\x01\x26"),
// 	},
// }
// func TestCBOREncode(t *testing.T) {
// 	for _, testCase := range CBOREncodeTestCases {
// 		assert := assert.New(t)

// 		var b []byte = CBOREncode(testCase.input)
// 		assert.Equal(testCase.output, b)
// 	}
// }


func TestWGSignExamples(t *testing.T) {
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
	// msg.headers.protected["ctyp"] = example.Input.Sign.Protected.Ctyp

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

	randReader := strings.NewReader(example.Input.RngDescription)

	// TODO: preprocess input to have a reasonable format
	output, err, ToBeSigned := Sign(&msg, &privateKey, randReader)
	assert.Nil(err)

	toSign := strings.ToUpper(hex.EncodeToString(ToBeSigned))
	// log.Println(fmt.Printf("ToBeSigned %+v", ToBeSigned))
	assert.Equal(example.Intermediates.Signers[0].ToBeSignHex, toSign, "sig_signature wrong")

	// signature from the example
	assert.Equal("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A", strings.ToUpper(hex.EncodeToString(output.signatures[0].signature)), "signature wrong")

	signed := strings.ToUpper(hex.EncodeToString(CBOREncode(output)))
	log.Println(fmt.Printf("signed %+v", signed))

	assert.Equal(example.Output.Cbor, signed, "CBOR encoded message wrong")

	// check for matching cbor, diag(cbor)
	// assert.Equal(output, example.Output.Cbor)

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
}
