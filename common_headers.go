package cose

import (
	"crypto"
	"errors"
	"fmt"
	generated "github.com/mozilla-services/go-cose/generated"
	"log"
)

// Headers - maps of protected and unprotected tags
type Headers struct {
	protected   map[interface{}]interface{}
	unprotected map[interface{}]interface{}
}

// NewHeaders -
// TODO: replace if this doesn't do validation
func NewHeaders(
	protected map[interface{}]interface{},
	unprotected map[interface{}]interface{}) (h *Headers) {
	return &Headers{
		protected:   protected,
		unprotected: unprotected,
	}
}

// MarshalBinary serializes the headers for CBOR (untagged)
func (h *Headers) MarshalBinary() (data []byte, err error) {
	// TODO: include unprotected?
	return h.EncodeProtected(), nil
}

// UnmarshalBinary not implemented; panics
func (h *Headers) UnmarshalBinary(data []byte) (err error) {
	panic("unsupported Headers.UnmarshalBinary")
}

// EncodeUnprotected returns headers with shortened tags
func (h *Headers) EncodeUnprotected() (encoded map[interface{}]interface{}) {
	return CompressHeaders(h.unprotected)
}

// EncodeProtected can panic
// TODO: check for dups in maps
func (h *Headers) EncodeProtected() (bstr []byte) {
	if h == nil {
		panic("Cannot encode nil Headers")
	}

	if h.protected == nil || len(h.protected) < 1 {
		return []byte("")
	}

	encoded, err := Marshal(CompressHeaders(h.protected))
	if err != nil {
		log.Fatalf("Marshal error of protected headers %s", err)
	}
	return encoded
}

// DecodeProtected Unmarshals from interface{}
func (h *Headers) DecodeProtected(o interface{}) (err error) {
	b, ok := o.([]byte)
	if !ok {
		return fmt.Errorf("error casting protected header bytes; got %T", o)
	}
	if len(b) <= 0 {
		return nil
	}

	protected, err := Unmarshal(b)
	if err != nil {
		return fmt.Errorf("error CBOR decoding protected header bytes; got %T", protected)
	}
	protectedMap, ok := protected.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("error casting protected to map; got %T", protected)
	}

	h.protected = protectedMap
	return nil
}

// DecodeUnprotected Unmarshals from interface{}
func (h *Headers) DecodeUnprotected(o interface{}) (err error) {
	msgHeadersUnprotected, ok := o.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("error decoding unprotected header as map[interface {}]interface {}; got %T", o)
	}
	h.unprotected = msgHeadersUnprotected
	return nil
}

// Decode loads a two element interface{} slice into itself
func (h *Headers) Decode(o []interface{}) (err error) {
	if len(o) != 2 {
		panic(fmt.Sprintf("can only decode headers from 2-item array; got %d", len(o)))
	}
	err = h.DecodeProtected(o[0])
	if err != nil {
		return err
	}
	err = h.DecodeUnprotected(o[1])
	if err != nil {
		return err
	}
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
		return 0, errors.New("No common COSE tag for label")
	}
}

// GetCommonHeaderTagOrPanic for consts strings returns the CBOR label for a string
func GetCommonHeaderTagOrPanic(label string) (tag int) {
	tag, err := GetCommonHeaderTag(label)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Failed to find a tag for label %s", label))
	}
	return tag
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
		return "", errors.New("No common COSE label for tag")
	}
}

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

// GetAlgByName returns a generated.COSEAlgorithm for an IANA name
func GetAlgByName(name string) (alg *generated.COSEAlgorithm, err error) {
	for _, alg := range generated.COSEAlgorithms {
		if alg.Name == name {
			return &alg, nil
		}
	}
	return nil, fmt.Errorf("Algorithm named %s not found", name)
}

// GetAlgByNameOrPanic returns a generated.COSEAlgorithm for an IANA name and panics otherwise
func GetAlgByNameOrPanic(name string) (alg *generated.COSEAlgorithm) {
	alg, err := GetAlgByName(name)
	if err != nil {
		panic(fmt.Sprintf("Unable to get algorithm named %s", name))
	}
	return alg
}

// GetAlgByValue returns a generated.COSEAlgorithm from an IANA value
func GetAlgByValue(value int64) (alg *generated.COSEAlgorithm, err error) {
	for _, alg := range generated.COSEAlgorithms {
		if int64(alg.Value) == value {
			return &alg, nil
		}
	}
	return nil, fmt.Errorf("Algorithm with value %v not found", value)
}

// GetAlgTag foo
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
		return 0, errors.New("Alg not implemented or invalid")
	}
}

// GetAlgLabel returns the CBOR alg label/name for the alg tag
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
		return "", errors.New("Alg not implemented or invalid")
	}
}

// CompressHeaders replaces string tags with their int values and alg tags with their IANA int values inverse of DecompressHeaders
func CompressHeaders(headers map[interface{}]interface{}) (compressed map[interface{}]interface{}) {
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
		compressed[k] = v
	}

	return compressed
}

// DecompressHeaders replaces  int values with string tags and alg int values with their IANA labels inverse of CompressHeaders
func DecompressHeaders(headers map[interface{}]interface{}) (decompressed map[interface{}]interface{}) {
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

	return decompressed
}

// getAlg returns the alg by label, int, or uint64 tag (as from Unmarshal)
func getAlg(h *Headers) (alg *generated.COSEAlgorithm, err error) {
	if tmp, ok := h.protected["alg"]; ok {
		if algName, ok := tmp.(string); ok {
			alg, err = GetAlgByName(algName)
			if err != nil {
				return nil, err
			}
			return alg, nil
		}
	} else if tmp, ok := h.protected[uint64(1)]; ok {
		if algValue, ok := tmp.(int64); ok {
			alg, err = GetAlgByValue(algValue)
			if err != nil {
				return nil, err
			}
			return alg, nil
		}
	} else if tmp, ok := h.protected[int(1)]; ok {
		if algValue, ok := tmp.(int); ok {
			alg, err = GetAlgByValue(int64(algValue))
			if err != nil {
				return nil, err
			}
			return alg, nil
		}
	}
	return nil, errors.New("Error fetching alg")
}

func getKeySizeForAlg(alg *generated.COSEAlgorithm) (keySize int, err error) {
	if alg.Value == GetAlgByNameOrPanic("ES256").Value {
		keySize = 32
	} else if alg.Value == GetAlgByNameOrPanic("ES384").Value {
		keySize = 48
	} else if alg.Value == GetAlgByNameOrPanic("ES512").Value {
		keySize = 66
	} else {
		err = errors.New("alg not implemented")
	}
	return keySize, err
}

func getExpectedArgsForAlg(alg *generated.COSEAlgorithm) (expectedKeyBitSize int, hash crypto.Hash, err error) {
	if alg.Value == GetAlgByNameOrPanic("ES256").Value {
		expectedKeyBitSize = 256
		hash = crypto.SHA256
	} else if alg.Value == GetAlgByNameOrPanic("ES384").Value {
		expectedKeyBitSize = 384
		hash = crypto.SHA384
	} else if alg.Value == GetAlgByNameOrPanic("ES512").Value {
		expectedKeyBitSize = 521 // i.e. P-521
		hash = crypto.SHA512
	} else if alg.Value == GetAlgByNameOrPanic("PS256").Value {
		expectedKeyBitSize = 256
		hash = crypto.SHA256
	} else {
		return -1, crypto.SHA256, errors.New("alg not implemented")
	}

	return expectedKeyBitSize, hash, nil
}
