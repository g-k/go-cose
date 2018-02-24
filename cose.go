
package cose

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"log"
	"io"
	"reflect"
	codec "github.com/ugorji/go/codec"
)

const (
	ContextSignature = "Signature"
	ContextSignature1 = "Signature1"
	ContextCounterSignature = "CounterSignature"
)


func compressHeaders(headers map[interface {}]interface {}) (encoded map[interface {}]interface {}) {
	fmt.Println(fmt.Printf("ENCODING (from compressHeaders) %+v", headers))

	encoded = map[interface{}]interface{}{}

	for k, v := range headers {
		kstr, kok := k.(string)
		vstr, vok := v.(string)
		if kok {
			tag, err := GetCommonHeaderTag(kstr)
			if err == nil {
				k = tag

				if (kstr == "alg" && vok) {
					at, err := GetAlgTag(vstr)
					if err == nil {
						v = at
					}
				}
			}
		}
		if vok && kstr != "alg" {
			v = []byte(vstr)
		}
		encoded[k] = v
	}

	fmt.Println(fmt.Printf("ENCODED (from compressHeaders) %+v", encoded))
	return encoded
}


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
func (h *COSEHeaders) EncodeUnprotected() (encoded map[interface{}]interface{}) {
	return compressHeaders(h.unprotected)
}
func (h *COSEHeaders) EncodeProtected() (bstr []byte) {
	// TODO: check for dups in maps
	if len(h.protected) < 1 {
		return []byte("")
	}

	return CBOREncode(compressHeaders(h.protected))
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
// func (s *COSESignature) MarshalBinary() (data []byte, err error) {
// 	return CBOREncode([]interface{}{
// 		s.headers.EncodeProtected(),
// 		s.headers.EncodeUnprotected(),
// 		s.signature,
// 	}), nil
// }
// func (s *COSESignature) UnmarshalBinary(data []byte) (err error) {
// 	panic("unsupported")
// }



type COSEExt struct{}
func (x COSEExt) UpdateExt(dest interface{}, v interface{}) {
	panic("unsupported")
}
func (x COSEExt) ConvertExt(v interface{}) interface{} {
	fmt.Println(fmt.Printf("ENCODING %v", v))
	message, ok := v.(*COSESignMessage)
	if !ok {
		panic(fmt.Sprintf("unsupported format expecting COSESignMessage; got %T", v))
	}

	// encoded := h.EncodeProtected()
	// fmt.Println(fmt.Printf("ENCODED %v", encoded))

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


func GetCOSEHandle() (h *codec.CborHandle) {
	h = new(codec.CborHandle)
	h.IndefiniteLength = false  // no streaming

	var cExt COSEExt

	// COSE Message CBOR tags from Table 1: COSE Message Identification
	// https://tools.ietf.org/html/rfc8152#section-2
	h.SetInterfaceExt(reflect.TypeOf(COSESignMessage{}), 98, cExt)

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
func Sign(message *COSESignMessage,
	key *ecdsa.PrivateKey,
	randReader io.Reader) (result *COSESignMessage, err error, ToBeSigned []byte) {
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
	ToBeSigned = CBOREncode(sig_structure)
	fmt.Println(fmt.Printf("%+v", ToBeSigned))

	// 3.  Call the signature creation algorithm passing in K (the key to
	//     sign with), alg (the algorithm to sign with), and ToBeSigned (the
	//     value to sign).
	if message.signatures[0].headers.protected["alg"] != "ES256" {
		panic("Not implemented.")
	}

	var hash crypto.Hash

	// ES256
	// expectedBitSize := 256
	hash = crypto.SHA256

	// TODO: if provided privateKey verify alg, bitsize, and supported key_ops in protected
	curveBits := key.Curve.Params().BitSize

	hasher := hash.New()

	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(ToBeSigned)
	hashed := hasher.Sum(nil)

	// https://tools.ietf.org/html/rfc8152#section-8.1
	r, s, err := ecdsa.Sign(randReader, key, hashed)
	if err != nil {
		panic(fmt.Errorf("ecdsa.Sign error %s", err))
	}
	// assert r and s are the same length will be the same length as the length of the key used for the signature process

	fmt.Println(fmt.Printf("\nr: %+v\ns: %+v\n", r, s))

	// The signature is encoded by converting the integers into
	// byte strings of the same length as the key size.  The
	// length is rounded up to the nearest byte and is left padded
	// with zero bits to get to the correct length.  The two
	// integers are then concatenated together to form a byte
	// string that is the resulting signature.
	keyBytes := curveBits / 8
	if curveBits % 8 > 0 {
		keyBytes += 1
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	sig := append(rBytesPadded, sBytesPadded...)

	// 4.  Place the resulting signature value in the 'signature' field of the array.
	message.signatures[0].signature = sig
	// fmt.Println(fmt.Printf("%+v", message))
	return message, nil, ToBeSigned
}
