

package cose


import (
	// "bytes"
	// "math/big"
	// "crypto"
	// "crypto/ecdsa"
	"fmt"
	"reflect"
	codec "github.com/ugorji/go/codec"
)

// Marshal returns the CBOR encoding of param o
func Marshal(o interface{}) (b []byte, err error) {
	var enc *codec.Encoder = codec.NewEncoderBytes(&b, GetCOSEHandle())

	err = enc.Encode(o)
	return b, err
}
// Unmarshal decodes CBOR bytes into param o
// TODO: decode into object inplace to implement the more encoding interface func Unmarshal(data []byte, v interface{}) error
// TODO: decode with readers for better interop in autograph
func Unmarshal(b []byte) (o interface{}, err error) {
	var dec *codec.Decoder = codec.NewDecoderBytes(b, GetCOSEHandle())

	err = dec.Decode(&o)
	return o, err
}

// Ext a codec.cbor extension
type Ext struct{}
// ConvertExt blah
func (x Ext) ConvertExt(v interface{}) interface{} {
	fmt.Println(fmt.Printf("ENCODING %v", v))
	message, ok := v.(*SignMessage)
	if !ok {
		panic(fmt.Sprintf("unsupported format expecting to encode SignMessage; got %T", v))
	}

	sigs := make([]interface{}, len(message.signatures))
	for i, s := range message.signatures {
		sigs[i] = []interface{}{
			s.headers.EncodeProtected(),
			s.headers.EncodeUnprotected(),
			s.signature,
		}
	}

	return []interface{}{
		message.headers.EncodeProtected(),
		message.headers.EncodeUnprotected(),
		[]byte(message.payload),
		sigs,
	}
}

// UpdateExt blah
// TODO: decompress headers too?
func (x Ext) UpdateExt(dest interface{}, v interface{}) {
	// fmt.Println(fmt.Sprintf("v: %x", v))

	var src, vok = v.([]interface{})
	if !vok {
		panic(fmt.Sprintf("unsupported format expecting to decode from []interface{}; got %T", v))
	}
	if len(src) != 4 {
		panic(fmt.Sprintf("can only decode SignMessage with 4 fields; got %d", len(src)))
	}
	// fmt.Println(fmt.Sprintf("src[0]: %+v %T", src[0], src[0]))

	var msgHeaders = NewHeaders(map[interface {}] interface{}{}, map[interface {}] interface{}{})
	err := msgHeaders.DecodeProtected(src[0])
	if err != nil {
		panic(fmt.Sprintf("error decoding protected header bytes; got %s", err))
	}
	err = msgHeaders.DecodeUnprotected(src[1])
	if err != nil {
		panic(fmt.Sprintf("error decoding unprotected header map; got %s", err))
	}
	// fmt.Println(fmt.Printf("DECODING: %T %+v", msgHeadersUnprotected, msgHeadersUnprotected))

	var payload, pok = src[2].([]byte)
	if !pok {
		panic(fmt.Sprintf("error decoding msg payload decode from interface{} to []byte; got %T", src[2]))
	}

	var m = NewSignMessage(payload)
	var message = &m
	message.SetHeaders(msgHeaders)

	var sigs, sok = src[3].([]interface {})
	if !sok {
		panic(fmt.Sprintf("error decoding sigs; got %T", src[3]))
	}
	for _, sig := range sigs {
		sigT := NewSignature()
		sigT.Decode(sig)
		message.AddSignature(sigT)
	}
	// fmt.Println(fmt.Printf("DECODED sigs: %T %+v", message.signatures, message.signatures))

	destMessage, ok := dest.(*SignMessage)
	if !ok {
		panic(fmt.Sprintf("unsupported format expecting to decode into *SignMessage; got %T", dest))
	}
	*destMessage = *message
}


// GetCOSEHandle returns a codec.CborHandle with Extensions registered
// for the COSE SignMessage CBOR Tag (98)
func GetCOSEHandle() (h *codec.CborHandle) {
	h = new(codec.CborHandle)
	h.IndefiniteLength = false  // no streaming
	h.Canonical = true // sort map keys

	var cExt Ext

	// COSE Message CBOR tags from
	// https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags

	// h.SetInterfaceExt(reflect.TypeOf(COSEEncrypt0Message{}), 16, cExt)
	// h.SetInterfaceExt(reflect.TypeOf(COSEMAC0Message{}), 17, cExt)
	// h.SetInterfaceExt(reflect.TypeOf(COSESign1Message{}), 18, cExt)

	// h.SetInterfaceExt(reflect.TypeOf(COSEEncryptMessage{}), 96, cExt)
	// h.SetInterfaceExt(reflect.TypeOf(COSEMACMessage{}), 97, cExt)
	h.SetInterfaceExt(reflect.TypeOf(SignMessage{}), 98, cExt)

	return h
}
