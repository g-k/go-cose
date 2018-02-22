
package cose

import (
	// "crypto"
	"fmt"
	"log"
	"testing"
	"encoding/hex"
	"github.com/g-k/go-cose/test"
	"github.com/stretchr/testify/assert"
	"strings"
)


var CBOREncodeTestCases = []struct {
	name string
	input interface{}
	output interface{}
}{
	{
		"empty bstr",
		[]byte(""),
		[]byte("\x40"),
	},
	{
		"alg header",
		COSEHeaders{
			protected: map[interface{}]interface{}{"alg": "ES256"},
			unprotected: map[interface{}]interface{}{},
		},
		// 0x43 for bytes h'A10126'
		// decoding h'A10126' gives:
		//     A1    # map(1)
		//       01 # unsigned(1)
		//       26 # negative(6)
		[]byte("\x43\xA1\x01\x26"),
	},
}
func TestCBOREncode(t *testing.T) {
	for _, testCase := range CBOREncodeTestCases {
		assert := assert.New(t)

		var b []byte = CBOREncode(testCase.input)
		assert.Equal(testCase.output, b)
	}
}


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
	// var key = crypto.PrivateKey.New()

	// TODO: preprocess input to have a reasonable format
	output, err := Sign(&msg, nil)
	// log.Println(fmt.Printf("out %+v", output))

	assert.Nil(err)

	ToBeSigned := strings.ToUpper(hex.EncodeToString(output))

	assert.Equal(example.Intermediates.Signers[0].ToBeSignHex, ToBeSigned)

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
