
package cose

import (
	"crypto"
	"fmt"
	"log"
	// "reflect"
	codec "github.com/ugorji/go/codec"
)

const (
	ContextSignature = "Signature"
	ContextSignature1 = "Signature1"
	ContextCounterSignature = "CounterSignature"
)

type COSEHeaders struct {
	protected map[interface{}]interface{}
	unprotected map[interface{}]interface{}
}
func (h *COSEHeaders) MarshalBinary() (data []byte, err error) {
	return h.EncodeProtected(), nil
}
func (h *COSEHeaders) UnmarshalBinary(data []byte) (err error) {
	panic("unsupported")
}
func (h *COSEHeaders) EncodeProtected() (bstr []byte) {
	if len(h.protected) < 1 {
		return []byte("")
	}

	encoded := map[interface{}]interface{}{}

	for k, v := range h.protected {
		s, ok := k.(string)
		if ok {
			tag, err := GetCommonHeaderTag(s)
			if err == nil {
				algs, ok := v.(string)
				if s == "alg" && ok {
					at, err := GetAlgTag(algs)
					if err == nil {
						encoded[tag] = at
					} else {
						encoded[tag] = v
					}
				} else {
					encoded[tag] = v
				}
			} else {
				encoded[k] = v
			}
		} else {
			encoded[k] = v
		}
	}

	fmt.Println(fmt.Printf("ENCODED (from headers) %+v", encoded))
	return CBOREncode(encoded)
}
func (h *COSEHeaders) Decode() {
	panic("unsupported")
}


// COSESignMessage https://tools.ietf.org/html/rfc8152#section-4.1
type COSESignMessage struct {
	headers *COSEHeaders
	payload []byte
	signatures []COSESignature
}
type COSESignature struct {
	headers *COSEHeaders
	signature []byte
}



type COSEExt struct{}
func (x COSEExt) UpdateExt(dest interface{}, v interface{}) {
	panic("unsupported")
}
func (x COSEExt) ConvertExt(v interface{}) interface{} {
	fmt.Println(fmt.Printf("ENCODING %v", v))
	h, ok := v.(*COSEHeaders)
	if ok {
		encoded := h.EncodeProtected()
		fmt.Println(fmt.Printf("ENCODED %v", encoded))
		return encoded
	} else {
		panic(fmt.Sprintf("unsupported format expecting COSEHeaders; got %T", v))
	}
	return v
}


func GetCOSEHandle() (h *codec.CborHandle) {
	h = new(codec.CborHandle)
	h.IndefiniteLength = false  // no streaming

	// var cExt COSEExt

	// COSE Message CBOR tags from Table 1: COSE Message Identification
	// https://tools.ietf.org/html/rfc8152#section-2
	// h.SetInterfaceExt(reflect.TypeOf(COSESignMessage{}), 98, cExt)


	// h.SetInterfaceExt(reflect.TypeOf(COSEHeaders{}), 20200, cExt)

	return h
}

func CBOREncode(o interface{}) (b []byte) {
	var enc *codec.Encoder = codec.NewEncoderBytes(&b, GetCOSEHandle())

	err := enc.Encode(o)
	if err != nil {
		log.Fatalf("Encoding error %s", err)
	}
	return b
}


// TODO: rewrite as Signer(kid, alg key config).Sign(payload, ext_data)
// https://tools.ietf.org/html/rfc8152#section-4
func Sign(
	message *COSESignMessage,
	key *crypto.PrivateKey) (result []byte, err error) {
	// Signing and Verification Process
	// https://tools.ietf.org/html/rfc8152#section-4.4
	//
	// 1.  Create a Sig_structure and populate it with the appropriate fields.
	// Sig_structure = [
	//     context : "Signature" / "Signature1" / "CounterSignature",
	//     body_protected : empty_or_serialized_map,
	//     ? sign_protected : empty_or_serialized_map,
	//     external_aad : bstr,
	//     payload : bstr
	// ]
	sig_structure := []interface{}{
		ContextSignature,
		message.headers.EncodeProtected(),
		message.signatures[0].headers.EncodeProtected(),
		[]byte(""),  // TODO: pass as arg
		message.payload,
	}

	// 2.  Create the value ToBeSigned by encoding the Sig_structure to a
	//     byte string, using the encoding described in Section 14.
	b := CBOREncode(sig_structure)
	fmt.Println(fmt.Printf("%+v", b))

	return b, nil

	// 3.  Call the signature creation algorithm passing in K (the key to
	//     sign with), alg (the algorithm to sign with), and ToBeSigned (the
	//     value to sign).


	// 4.  Place the resulting signature value in the 'signature' field of the array.

}
