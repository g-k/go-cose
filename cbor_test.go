package cose

import (
	"fmt"
	"errors"
	"reflect"
	codec "github.com/ugorji/go/codec"
	"github.com/mozilla-services/go-cose/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

/// Tests for encoding and decoding go-cose objects to and from CBOR
// TODO: combine into a single test that: round trips and checks expected marshal / unmarshal results

type CBORTestCase struct{
	name   string
	obj    interface{}
	bytes  []byte
}

var CBORTestCases = []CBORTestCase{
	// golang data structures
	{
		"empty bstr",
		[]byte(""),
		[]byte("\x40"), // bytes(0) i.e. ""
	},
	{
		"generic interface map",
		map[interface{}]interface{}{uint64(1): int64(-7)},
		util.HexToBytesOrDie("A10126"),
	},

	// Headers
	{
		"empty headers",
		Headers{
			protected:   map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		[]byte("\x40"),
	},
	{
		"alg in protected header",
		Headers{
			protected:   map[interface{}]interface{}{"alg": "ES256"},
			unprotected: map[interface{}]interface{}{},
		},
		// 0x43 for bytes h'A10126'
		// decoding h'A10126' gives:
		//     A1    # map(1)
		//       01 # unsigned(1)
		//       26 # negative(7)
		[]byte("\x43\xA1\x01\x26"),
	},
	{
		"alg in unprotected header",
		Headers{
			protected: map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{"alg": "ES256"},
		},
		[]byte("\x40"),
	},
	{
		"duplicate key across protected and unprotected maps",
		// TODO: throw a duplicate key error?
		Headers{
			protected: map[interface{}]interface{}{
				"alg": "ES256",
			},
			unprotected: map[interface{}]interface{}{
				"alg": "PS256",
			},
		},
		util.HexToBytesOrDie("43a10126"), // see "alg in protected header" comment
	},
	// TODO: test this despite golang not allowing duplicate key "alg" in map literal
	// {
	// 	"duplicate key in protected",
	// 	[]byte(""),
	// 	Headers{
	// 		protected: map[interface{}]interface{}{
	// 			"alg": "ES256",
	// 			"alg": "PS256",
	// 		},
	// 		unprotected: map[interface{}]interface{}{},
	// 	},
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
}


func MarshalsToExpectedBytes(t *testing.T, testCase CBORTestCase) {
	assert := assert.New(t)

	bytes, err := Marshal(testCase.obj)
	assert.Nil(err)

	assert.Equal(testCase.bytes, bytes)
}

func UnmarshalsToExpectedInterface(t *testing.T, testCase CBORTestCase) {
	assert := assert.New(t)

	_, err := Unmarshal(testCase.bytes)
	assert.Nil(err)

	// TODO: support untagged messages
	// assert.Equal(testCase.obj, obj)
}

func RoundtripsToExpectedBytes(t *testing.T, testCase CBORTestCase) {
	assert := assert.New(t)

	obj, err := Unmarshal(testCase.bytes)
	assert.Nil(err)

	bytes, err := Marshal(obj)
	assert.Nil(err)

	assert.Equal(testCase.bytes, bytes)
}

func TestCBOREncoding(t *testing.T) {
	for _, testCase := range CBORTestCases {
		t.Run(fmt.Sprintf("%s: MarshalsToExpectedBytes", testCase.name), func(t *testing.T) {
			MarshalsToExpectedBytes(t, testCase)
		})

		t.Run(fmt.Sprintf("%s: UnmarshalsToExpectedInterface", testCase.name), func(t *testing.T) {
			UnmarshalsToExpectedInterface(t, testCase)
		})

		t.Run(fmt.Sprintf("%s: RoundtripsToExpectedBytes", testCase.name), func(t *testing.T) {
			RoundtripsToExpectedBytes(t, testCase)
		})
	}
}

func TestCBOREncodingErrsOnUnexpectedType(t *testing.T) {
	assert := assert.New(t)

	type Flub struct {
		foo string
	}
	obj := Flub{
		foo: "not a SignMessage",
	}

	h := GetCOSEHandle()
	var cExt Ext
	h.SetInterfaceExt(reflect.TypeOf(obj), SignMessageCBORTag, cExt)

	var b []byte
	var enc *codec.Encoder = codec.NewEncoderBytes(&b, h)

	err := enc.Encode(obj)
	assert.Equal(errors.New("cbor encode error: unsupported format expecting to encode SignMessage; got *cose.Flub"), err)
}
