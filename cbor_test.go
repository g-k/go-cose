
package cose

import (
	"fmt"
	"github.com/g-k/go-cose/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

/// Tests for encoding and decoding go-cose objects to and from CBOR

var CBOREncodeTestCases = []struct {
	name string
	input interface{}
	output interface{}
}{
	{
		"empty bstr",
		[]byte(""),
		[]byte("\x40"), // bytes(0) / ""
	},
	// {
	// 	"empty header",
	// 	COSEHeaders{
	// 		protected: map[interface{}]interface{}{},
	// 		unprotected: map[interface{}]interface{}{},
	// 	},
	// 	[]byte("\x40\x40"),
	// },
	{
		"alg in protected header",
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
	// {
	// 	"alg in unprotected header",
	// 	COSEHeaders{
	// 		protected: map[interface{}]interface{}{},
	// 		unprotected: map[interface{}]interface{}{"alg": "ES256"},
	// 	},
	// 	[]byte(""),
	// },
	// golang doesn't allow this duplicate key "alg" in map literal
	// {
	// 	"duplicate key in protected",
	// 	COSEHeaders{
	// 		protected: map[interface{}]interface{}{
	// 			"alg": "ES256",
	// 			"alg": "PS256",
	// 		},
	// 		unprotected: map[interface{}]interface{}{},
	// 	},
	// 	[]byte(""),
	// },
	// {
	// 	"duplicate key in unprotected",
	// 	COSEHeaders{
	// 		protected: map[interface{}]interface{}{},
	// 		unprotected: map[interface{}]interface{}{
	// 			"alg": "ES256",
	// 			"alg": "PS256",
	// 		},
	// 	},
	// 	[]byte(""),
	// },
	// {
	// 	"duplicate key across protected and unprotected maps",
	// 	COSEHeaders{
	// 		protected: map[interface{}]interface{}{
	// 			"alg": "ES256",
	// 		},
	// 		unprotected: map[interface{}]interface{}{
	// 			"alg": "PS256",
	// 		},
	// 	},
	// 	[]byte(""),
	// },
}
func TestCBOREncode(t *testing.T) {
	for _, testCase := range CBOREncodeTestCases {
		assert := assert.New(t)
		assert.Equal(
			testCase.output,
			CBOREncode(testCase.input),
			fmt.Sprintf("%s failed", testCase.name))
	}
}


var CBORDecodeTestCases = []struct {
	name string
	input []byte
	output interface{}
}{
	{
		"empty bstr",
		[]byte("\x40"),
		[]byte(""),
	},
	{
		"wg sign-tests/sign-pass-01.json",
		[]byte(test.HexToBytesOrDie("D8628441A0A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A")),
		COSESignMessage{
			headers: &COSEHeaders{
				protected: map[interface {}]interface {}{},
				unprotected: map[interface {}]interface {}{},
			},
			payload: []byte("This is the content."),
			signatures: []COSESignature{
					COSESignature{
						headers: &COSEHeaders{
							// should be -6
							protected: map[interface {}]interface{}{uint64(1): int64(-7)},
							unprotected: map[interface {}]interface{}{uint64(4): []byte("11")},
						},
						signature: test.HexToBytesOrDie("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"),
					},
			},
		},
	},
}
func TestCBORDecode(t *testing.T) {
	for _, testCase := range CBORDecodeTestCases {
		assert := assert.New(t)

		output, err := CBORDecode(testCase.input)
		assert.Nil(err)
		assert.Equal(
			testCase.output,
			output,
			fmt.Sprintf("%s failed", testCase.name))
	}
}
