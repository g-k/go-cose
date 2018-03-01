package cose

import (
	"errors"
	"fmt"
	"log"
)


type COSEHeaders struct {
	protected map[interface{}]interface{}
	unprotected map[interface{}]interface{}
}
func NewCOSEHeaders(
	protected map[interface{}]interface{},
	unprotected map[interface{}]interface{}) (h *COSEHeaders) {
	return &COSEHeaders{
		protected: protected,
		unprotected: unprotected,
	}
}
func (h *COSEHeaders) MarshalBinary() (data []byte, err error) {
	// TODO: include unprotected
	return h.EncodeProtected(), nil
}
func (h *COSEHeaders) UnmarshalBinary(data []byte) (err error) {
	panic("unsupported COSEHeaders.UnmarshalBinary")
}
func (h *COSEHeaders) EncodeUnprotected() (encoded map[interface{}]interface{}) {
	return CompressHeaders(h.unprotected)
}
func (h *COSEHeaders) EncodeProtected() (bstr []byte) {
	// TODO: check for dups in maps
	// fmt.Println(fmt.Printf("EncodeProtected\n%T %+v %v", h.protected, h.protected, h.protected == nil))
	if h == nil {
		panic("Cannot encode nil COSEHeaders")
	}

	if h.protected == nil || len(h.protected) < 1 {
		return []byte("")
	}

	encoded, err := CBOREncode(CompressHeaders(h.protected))
	if err != nil {
		log.Fatalf("CBOREncode error of protected headers %s", err)
	}
	return encoded
}
func (h *COSEHeaders) DecodeProtected(o interface {}) (err error) {
	b, ok := o.([]byte)
	if !ok {
		return errors.New(fmt.Sprintf("error casting protected header bytes; got %T", o))
	}
	if len(b) <= 0 {
		return nil
	}

	protected, err := CBORDecode(b)
	if err != nil {
		return errors.New(fmt.Sprintf("error CBOR decoding protected header bytes; got %T", protected))
	}
	protectedMap, ok := protected.(map[interface {}]interface {})
	if !ok {
		return errors.New(fmt.Sprintf("error casting protected to map; got %T", protected))
	}

	h.protected = protectedMap
	return nil
}
func (h *COSEHeaders) DecodeUnprotected(o interface {}) (err error) {
	msgHeadersUnprotected, ok := o.(map[interface {}]interface {})
	if !ok {
		return errors.New(fmt.Sprintf("error decoding unprotected header as map[interface {}]interface {}; got %T", o))
	}
	h.unprotected = msgHeadersUnprotected
	return nil
}


// GetCommonHeaderTag returns the CBOR tag for the map label
//
// using Common COSE Headers Parameters Table 2
// https://tools.ietf.org/html/rfc8152#section-3.1
func GetCommonHeaderTag(label string) (tag int, err error) {
	switch label {
	case "alg":
		return 1, nil
	case "crit":
		return 2, nil
	case "content type":
		return 3, nil
	case "kid":
		return 4, nil
	case "IV":
		return 5, nil
	case "Partial IV":
		return 6, nil
	case "counter signature":
		return 7, nil
	default:
		return 0, errors.New("No common COSE tag for label.")
	}
}

// GetCommonHeaderLabel returns the CBOR label for the map tag
// inverse of GetCommonHeaderTag
func GetCommonHeaderLabel(tag int) (label string, err error) {
	switch tag {
	case 1:
		return "alg", nil
	case 2:
		return "crit", nil
	case 3:
		return "content type", nil
	case 4:
		return "kid", nil
	case 5:
		return "IV", nil
	case 6:
		return "Partial IV", nil
	case 7:
		return "counter signature", nil
	default:
		return "", errors.New("No common COSE label for tag.")
	}
}

// GetCommonHeaderValue
// func GetCommonHeaderValue(label string, value string) (tag int, err error) {
// 	switch label {
// 	case "alg":
// 		GetAlgTag(value)
// 	default:
// 	}
// }

// GetAlgTag returns the CBOR tag for the alg label value
//
//
// From the spec:
//
// NOTE: The assignment of algorithm identifiers in this document was
// done so that positive numbers were used for the first layer objects
// (COSE_Sign, COSE_Sign1, COSE_Encrypt, COSE_Encrypt0, COSE_Mac, and
// COSE_Mac0).  Negative numbers were used for second layer objects
// (COSE_Signature and COSE_recipient).
//
// https://www.iana.org/assignments/cose/cose.xhtml#header-algorithm-parameters
//
// https://tools.ietf.org/html/rfc8152#section-16.4
func GetAlgTag(label string) (tag int, err error) {
	switch label {
	case "PS256":
		return -37, nil
	case "ES256":
		return -7, nil
	case "ES384":
		return -35, nil
	case "ES512":
		return -36, nil
	case "EdDSA":
		return -8, nil
	case "HMAC 256/64":
		return 4, nil
	case "HMAC 256/256":
		return 5, nil
	case "HMAC 384/384":
		return 6, nil
	case "HMAC 512/512":
		return 7, nil
	case "AES-MAC 128/64":
		return 14, nil
	case "AES-MAC 256/64":
		return 15, nil
	case "AES-MAC 128/128":
		return 25, nil
	case "AES-MAC 256/128":
		return 26, nil
	case "A128GCM":
		return 1, nil
	case "A192GCM":
		return 2, nil
	case "A256GCM":
		return 3, nil
	case "AES-CCM-16-64-128":
		return 10, nil
	case "ChaCha20/Poly1305":
		return 24, nil
	case "direct":
		return -6, nil
	default:
		return 0, errors.New("Alg not implemented or invalid.")
	}
}

// GetAlgTag returns the CBOR alg label/name for the alg tag
func GetAlgLabel(tag int) (label string, err error) {
	switch tag {
	case -37:
		return "PS256", nil
	case -7:
		return "ES256", nil
	case -35:
		return "ES384", nil
	case -36:
		return "ES512", nil
	case -8:
		return "EdDSA", nil
	case 4:
		return "HMAC 256/64", nil
	case 5:
		return "HMAC 256/256", nil
	case 6:
		return "HMAC 384/384", nil
	case 7:
		return "HMAC 512/512", nil
	case 14:
		return "AES-MAC 128/64", nil
	case 15:
		return "AES-MAC 256/64", nil
	case 25:
		return "AES-MAC 128/128", nil
	case 26:
		return "AES-MAC 256/128", nil
	case 1:
		return "A128GCM", nil
	case 2:
		return "A192GCM", nil
	case 3:
		return "A256GCM", nil
	case 10:
		return "AES-CCM-16-64-128", nil
	default:
		return "", errors.New("Alg not implemented or invalid.")
	}
}

func CompressHeaders(headers map[interface{}]interface{}) (compressed map[interface{}]interface{}) {
	// fmt.Println(fmt.Printf("COMPRESSING %+v", headers))

	compressed = map[interface{}]interface{}{}

	for k, v := range headers {
		kstr, kok := k.(string)
		vstr, vok := v.(string)
		if kok {
			tag, err := GetCommonHeaderTag(kstr)
			if err == nil {
				k = tag

				if kstr == "alg" && vok {
					at, err := GetAlgTag(vstr)
					if err == nil {
						v = at
					}
				}
			}
		}
		// if vok && kstr != "alg" {
		// 	v = []byte(vstr)
		// }
		compressed[k] = v
	}

	// fmt.Println(fmt.Printf("COMPRESSED %+v", compressed))
	return compressed
}
func DecompressHeaders(headers map[interface{}]interface{}) (decompressed map[interface{}]interface{}) {
	// fmt.Println(fmt.Printf("DECOMPRESSING %+v", headers))

	decompressed = map[interface{}]interface{}{}

	for k, v := range headers {
		kint, kok := k.(int)
		vint, vok := v.(int)
		if kok {
			label, err := GetCommonHeaderLabel(kint)
			if err == nil {
				k = label
				if label == "alg" && vok {
					algLabel, err := GetAlgLabel(vint)
					if err == nil {
						v = algLabel
					}
				}
			}
		}
		decompressed[k] = v
	}

	// fmt.Println(fmt.Printf("DECOMPRESSED %+v", decompressed))
	return decompressed
}
