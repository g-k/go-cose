
package cose

import (
	// "fmt"
	// "testing"
	// "github.com/stretchr/testify/assert"
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
