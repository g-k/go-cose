

package cose


import (
	// "bytes"
	// "math/big"
	// "crypto"
	// "crypto/ecdsa"
	"fmt"
	"log"
	"reflect"
	codec "github.com/ugorji/go/codec"
)


func CBOREncode(o interface{}) (b []byte) {
	var enc *codec.Encoder = codec.NewEncoderBytes(&b, GetCOSEHandle())

	err := enc.Encode(o)
	if err != nil {
		log.Fatalf("Encoding error %s", err)
	}
	return b
}
func CBORDecode(b []byte) (o interface{}, err error) {
	// fmt.Println(fmt.Printf("CBORDecode decoding %+x", b))
	var dec *codec.Decoder = codec.NewDecoderBytes(b, GetCOSEHandle())

	err = dec.Decode(&o)
	if err != nil {
		log.Fatalf("CBORDecode decoding error %s", err)
	}

	// fmt.Println(fmt.Printf("CBORDecode decoded %+v", o))
	return o, err
}

type COSEExt struct{}
func (x COSEExt) ConvertExt(v interface{}) interface{} {
	fmt.Println(fmt.Printf("ENCODING %v", v))
	message, ok := v.(*COSESignMessage)
	if !ok {
		panic(fmt.Sprintf("unsupported format expecting to encode COSESignMessage; got %T", v))
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
func (x COSEExt) UpdateExt(dest interface{}, v interface{}) {
	var src, vok = v.([]interface{})
	if !vok {
		panic(fmt.Sprintf("unsupported format expecting to decode from []interface{}; got %T", v))
	}
	if len(src) != 4 {
		panic(fmt.Sprintf("can only decode COSESignMessage with 4 fields; got %d", len(src)))
	}

	// TODO: decompress headers too
	phb, ok := src[0].([]byte)
	if !ok {
		panic(fmt.Sprintf("error decoding protected header bytes; got %T", src[0]))
	}
	msgHeadersProtected, err := CBORDecode(phb)
	if err != nil {
		panic(fmt.Sprintf("error CBOR decoding protected header bytes; got %T", msgHeadersProtected))
	}
	msgHeadersProtectedMap, ok := msgHeadersProtected.(map[interface {}]interface {})
	if !ok {
		panic(fmt.Sprintf("error casting protected to map; got %T", msgHeadersProtected))
	}
	// fmt.Println(fmt.Printf("DECODING: %T %+v", msgHeadersProtectedMap, msgHeadersProtectedMap))

	msgHeadersUnprotected, ok := src[1].(map[interface {}]interface {})
	if !ok {
		panic(fmt.Sprintf("error decoding unprotected header bytes; got %T", src[1]))
	}
	// fmt.Println(fmt.Printf("DECODING: %T %+v", msgHeadersUnprotected, msgHeadersUnprotected))

	var payload, pok = src[2].([]byte)
	if !pok {
		panic(fmt.Sprintf("!!!? unsupported format expecting to decode from []interface{}; got %T", v))
	}

	message := &COSESignMessage{
		headers: &COSEHeaders{
			protected: msgHeadersProtectedMap,
			unprotected: msgHeadersUnprotected,
		},
		payload: payload,
		signatures: []COSESignature{},
	}

	var sigs, sok = src[3].([]interface {})
	if !sok {
		panic(fmt.Sprintf("error decoding sigs; got %T", src[3]))
	}
	for _, sig := range sigs {
		sig, sok = sig.([]interface {})
		if !sok {
			panic(fmt.Sprintf("error decoding sig; got %T", sig))
		}
		sig, sok = sig.([]interface {})
		if !sok {
			panic(fmt.Sprintf("error decoding sig; got %T", sig))
		}

		// if len(sig) != 3 {
		// 	panic(fmt.Sprintf("can only decode COSESignature with 3 items; got %d", len(sig)))
		// }

		phs, ok := src[0].([]byte)
		if !ok {
			panic(fmt.Sprintf("error decoding protected header bytes; got %T", src[0]))
		}
		sigHeadersProtected, err := CBORDecode(phs)
		if err != nil {
			panic(fmt.Sprintf("error CBOR decoding protected header bytes; got %T", sigHeadersProtected))
		}
		sigHeadersProtectedMap, ok := sigHeadersProtected.(map[interface {}]interface {})
		if !ok {
			panic(fmt.Sprintf("error casting protected to map; got %T", sigHeadersProtected))
		}
		// fmt.Println(fmt.Printf("DECODING: %T %+v", sigHeadersProtectedMap, sigHeadersProtectedMap))

		sigHeadersUnprotected, ok := src[1].(map[interface {}]interface {})
		if !ok {
			panic(fmt.Sprintf("error decoding unprotected header bytes; got %T", src[1]))
		}

		var signatureB, sbok = src[2].([]byte)
		if !sbok {
			panic(fmt.Sprintf("!!!? unsupported format expecting to decode from []interface{}; got %T", src[2]))
		}

		sigT := COSESignature{
			headers: &COSEHeaders{
				protected: sigHeadersProtectedMap,
				unprotected: sigHeadersUnprotected,
			},
			signature: []byte(signatureB),
		}

		fmt.Println(fmt.Printf("DECODING sig: %x %d", sigT.signature, len(sigT.signature) / 8))

		message.signatures = append(message.signatures, sigT)
	}
	// fmt.Println(fmt.Printf("DECODED sigs: %T %+v", message.signatures, message.signatures))

	if (len(message.signatures) != 1) {
		panic(fmt.Errorf("wtf? too few or many sigs %d", len(message.signatures)))
	}
	// fmt.Println(fmt.Printf("DECODED COSESignMessage: %T %+v", message, message))

	destMessage, ok := dest.(*COSESignMessage)
	if !ok {
		panic(fmt.Sprintf("unsupported format expecting to decode into *COSESignMessage; got %T", dest))
	}
	*destMessage = *message
}


func GetCOSEHandle() (h *codec.CborHandle) {
	h = new(codec.CborHandle)
	h.IndefiniteLength = false  // no streaming
	h.Canonical = true // sort map keys

	var cExt COSEExt

	// COSE Message CBOR tags
	// https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
	h.SetInterfaceExt(reflect.TypeOf(COSESignMessage{}), 98, cExt)

	// h.SetInterfaceExt(reflect.TypeOf(COSEHeaders{}), 20200, cExt)
	return h
}
