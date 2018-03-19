
package cose

import (
	"fmt"
	"github.com/g-k/go-cose/util"
	"github.com/stretchr/testify/assert"
	"testing"
	"reflect"
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
	{
		"empty header",
		Headers{
			protected: map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		[]byte("\x40"),
	},
	{
		"alg in protected header",
		Headers{
			protected: map[interface{}]interface{}{"alg": "ES256"},
			unprotected: map[interface{}]interface{}{},
		},
		// 0x43 for bytes h'A10126'
		// decoding h'A10126' gives:
		//     A1    # map(1)
		//       01 # unsigned(1)
		//       26 # negative(7)
		[]byte("\x43\xA1\x01\x26"),
	},
	// {
	// 	"alg in unprotected header",
	// 	Headers{
	// 		protected: map[interface{}]interface{}{},
	// 		unprotected: map[interface{}]interface{}{"alg": "ES256"},
	// 	},
	// 	[]byte(""),
	// },
	// golang doesn't allow this duplicate key "alg" in map literal
	// {
	// 	"duplicate key in protected",
	// 	Headers{
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
	// 	Headers{
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
	// 	Headers{
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
		t.Run(testCase.name, func (t *testing.T) {
			assert := assert.New(t)

			output, err := CBOREncode(testCase.input)
			assert.Nil(err, fmt.Sprintf("%s failed", testCase.name))
			assert.Equal(
				testCase.output,
				output,
				fmt.Sprintf("%s failed", testCase.name))
		})
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
		"a map",
		util.HexToBytesOrDie("A10126"),
		map[interface {}]interface {}{uint64(1): int64(-7)},
	},
	{
		"wg sign-tests/sign-pass-01.json",
		util.HexToBytesOrDie("D8628441A0A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"),
		SignMessage{
			headers: &Headers{
				protected: map[interface {}]interface {}{},
				unprotected: map[interface {}]interface {}{},
			},
			payload: []byte("This is the content."),
			signatures: []Signature{
					Signature{
						headers: &Headers{
							protected: map[interface {}]interface{}{uint64(1): int64(-7)},
							unprotected: map[interface {}]interface{}{uint64(4): []byte("11")},
						},
						signature: util.HexToBytesOrDie("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"),
					},
			},
		},
	},
	{
		"wg sign-tests/sign-pass-02.json",
		util.HexToBytesOrDie("D8628440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840CBB8DAD9BEAFB890E1A414124D8BFBC26BEDF2A94FCB5A882432BFF6D63E15F574EEB2AB51D83FA2CBF62672EBF4C7D993B0F4C2447647D831BA57CCA86B930A"),
		SignMessage{
			headers: &Headers{
				protected: map[interface {}]interface {}{},
				unprotected: map[interface {}]interface {}{},
			},
			payload: []byte("This is the content."),
			signatures: []Signature{
					Signature{
						headers: &Headers{
							protected: map[interface {}]interface{}{uint64(1): int64(-7)},
							unprotected: map[interface {}]interface{}{uint64(4): []byte("11")},
						},
						signature: util.HexToBytesOrDie("CBB8DAD9BEAFB890E1A414124D8BFBC26BEDF2A94FCB5A882432BFF6D63E15F574EEB2AB51D83FA2CBF62672EBF4C7D993B0F4C2447647D831BA57CCA86B930A"),
					},
			},
		},
	},
	{
		"wg sign-tests/sign-fail-02.json",
		util.HexToBytesOrDie("D8628440A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30B"),
		SignMessage{
			headers: &Headers{
				protected: map[interface {}]interface {}{},
				unprotected: map[interface {}]interface {}{},
			},
			payload: []byte("This is the content."),
			signatures: []Signature{
					Signature{
						headers: &Headers{
							protected: map[interface {}]interface{}{uint64(1): int64(-7)},
							unprotected: map[interface {}]interface{}{uint64(4): []byte("11")},
						},
						signature: util.HexToBytesOrDie("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30B"),
					},
			},
		},
	},
	{
		"wg sign-tests/sign-fail-03.json",
		util.HexToBytesOrDie("D8628440A054546869732069732074686520636F6E74656E742E818345A1013903E6A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"),
		SignMessage{
			headers: &Headers{
				protected: map[interface {}]interface {}{},
				unprotected: map[interface {}]interface {}{},
			},
			payload: []byte("This is the content."),
			signatures: []Signature{
					Signature{
						headers: &Headers{
							protected: map[interface {}]interface{}{uint64(1): int64(-999)},
							unprotected: map[interface {}]interface{}{uint64(4): []byte("11")},
						},
						signature: util.HexToBytesOrDie("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"),
					},
			},
		},
	},
	{
		"wg sign-tests/sign-fail-04.json",
		util.HexToBytesOrDie("D8628440A054546869732069732074686520636F6E74656E742E81834AA10167756E6B6E6F776EA1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"),
		SignMessage{
			headers: &Headers{
				protected: map[interface {}]interface {}{},
				unprotected: map[interface {}]interface {}{},
			},
			payload: []byte("This is the content."),
			signatures: []Signature{
					Signature{
						headers: &Headers{
							protected: map[interface {}]interface{}{uint64(1): string("unknown")},
							unprotected: map[interface {}]interface{}{uint64(4): []byte("11")},
						},
						signature: util.HexToBytesOrDie("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"),
					},
			},
		},
	},
	{
		"wg sign-tests/sign-fail-06.json",
		util.HexToBytesOrDie("D8628443A10300A054546869732069732074686520636F6E74656E742E818343A10126A1044231315840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"),
		SignMessage{
			headers: &Headers{
				protected: map[interface {}]interface {}{uint64(3): uint64(0)},
				unprotected: map[interface {}]interface {}{},
			},
			payload: []byte("This is the content."),
			signatures: []Signature{
					Signature{
						headers: &Headers{
							protected: map[interface {}]interface{}{uint64(1): int64(-7)},
							unprotected: map[interface {}]interface{}{uint64(4): []byte("11")},
						},
						signature: util.HexToBytesOrDie("E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A"),
					},
			},
		},
	},
}
func TestCBORDecode(t *testing.T) {
	for _, testCase := range CBORDecodeTestCases {
		t.Run(testCase.name, func (t *testing.T) {
			assert := assert.New(t)

			output, err := CBORDecode(testCase.input)
			assert.Nil(err)

			if reflect.TypeOf(testCase.output) != reflect.TypeOf(SignMessage{}) {
				return
			}
			msg, ok := output.(SignMessage)
			assert.True(ok, fmt.Sprintf("%s failed to cast to SignMessage", testCase.name))

			assert.Equal(
				testCase.output,
				msg,
				fmt.Sprintf("%s failed", testCase.name))
		})
	}
}
