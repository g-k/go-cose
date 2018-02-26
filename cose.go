
package cose

import (
	"bytes"
	"math/big"
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
func (h *COSEHeaders) Compress() {
}
func (h *COSEHeaders) MarshalBinary() (data []byte, err error) {
	// TODO: encode unprotected too
	return h.EncodeProtected(), nil
}
func (h *COSEHeaders) UnmarshalBinary(data []byte) (err error) {
	panic("unsupported COSEHeaders.UnmarshalBinary")
}
func (h *COSEHeaders) EncodeUnprotected() (encoded map[interface{}]interface{}) {
	return compressHeaders(h.unprotected)
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

	return CBOREncode(compressHeaders(h.protected))
}
func (h *COSEHeaders) Decode() {
	panic("unsupported COSEHeaders.Decode")
}


// COSESignMessage https://tools.ietf.org/html/rfc8152#section-4.1
type COSESignMessage struct {
	headers *COSEHeaders
	payload []byte
	signatures []COSESignature
}
func NewCOSESignMessage() (msg COSESignMessage) {
	msg = COSESignMessage{
		headers: &COSEHeaders{
			protected: map[interface{}]interface{}{},
			unprotected: map[interface{}]interface{}{},
		},
		payload: []byte(""),
		signatures: []COSESignature{
			{
				headers: &COSEHeaders{
					protected: map[interface{}]interface{}{},
					unprotected: map[interface{}]interface{}{},
				},
				signature: nil,
			},
		},
	}
	return msg
}

// COSESignature https://tools.ietf.org/html/rfc8152#section-4.1
type COSESignature struct {
	headers *COSEHeaders
	signature []byte
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


// https://github.com/r2ishiguro/vrf/blob/69d5bfb37b72b7b932ffe34213778bdb319f0438/go/vrf_ed25519/vrf_ed25519.go#L206
func I2OSP(b *big.Int, n int) []byte {
	os := b.Bytes()
	if n > len(os) {
		var buf bytes.Buffer
		buf.Write(make([]byte, n - len(os)))	// prepend 0s
		buf.Write(os)
		return buf.Bytes()
	} else {
		return os[:n]
	}
}


func hashSigStructure(message *COSESignMessage, key *ecdsa.PublicKey) []byte {
	if message.signatures == nil {
		panic("nil sigs")
	} else if len(message.signatures) < 1 {
		panic("no sig to hash")
	}

	sig_structure := []interface{}{
		ContextSignature,
		message.headers.EncodeProtected(),
		message.signatures[0].headers.EncodeProtected(),
		[]byte(""),  // TODO: pass as arg
		message.payload,
	}
	ToBeSigned := CBOREncode(sig_structure)

	var hash crypto.Hash

	// ES256
	// expectedBitSize := 256
	hash = crypto.SHA256

	// TODO: if provided privateKey verify alg, bitsize, and supported key_ops in protected

	hasher := hash.New()

	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(ToBeSigned)
	hashed := hasher.Sum(nil)

	return hashed
}


// TODO: rewrite as Signer(kid, alg key config).Sign(payload, ext_data)
// https://tools.ietf.org/html/rfc8152#section-4
func Sign(message *COSESignMessage, key *ecdsa.PrivateKey, randReader io.Reader) (result *COSESignMessage, err error, ToBeSigned []byte) {
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
	fmt.Println(fmt.Printf("ToBeSigned %+x", ToBeSigned))

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
	fmt.Println(fmt.Printf("hashed %+x", hashed))

	// https://tools.ietf.org/html/rfc8152#section-8.1
	r, s, err := ecdsa.Sign(randReader, key, hashed)
	if err != nil {
		panic(fmt.Errorf("ecdsa.Sign error %s", err))
	}
	// assert r and s are the same length will be the same length as the length of the key used for the signature process

	fmt.Println(fmt.Printf("\nr: %+v\ns: %+v\n %+x", r, s, hashed))

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
	sBytes := s.Bytes()
	fmt.Println(fmt.Printf("\nr: %+x\ns: %+x\n", rBytes, sBytes))

	// fmt.Println(fmt.Printf("\nPadded\nr: %+x\ns: %+x\n", rBytes, sBytes))

	n := keyBytes
	sig := make([]byte, 0)
	sig = append(sig, I2OSP(r, n)...)
	sig = append(sig, I2OSP(s, n)...)

	// 4.  Place the resulting signature value in the 'signature' field of the array.
	message.signatures[0].signature = sig
	// fmt.Println(fmt.Printf("%+v", message))
	return message, nil, ToBeSigned
}


func Verify(message *COSESignMessage, publicKey *ecdsa.PublicKey) (ok bool, err error) {
	hashed := hashSigStructure(message, publicKey)

	// ES256 / sha256
	keySize := 32

	// r and s from sig
	signature := message.signatures[0].signature
	fmt.Println(fmt.Printf("(Verify) signature %x %d", signature, len(signature) / 8))
	if len(signature) != 2 * keySize {
		panic(fmt.Sprintf("invalid signature length: %d", len(signature)))
	}

	r := big.NewInt(0).SetBytes(signature[:keySize])
	s := big.NewInt(0).SetBytes(signature[keySize:])

	return ecdsa.Verify(publicKey, hashed, r, s), nil
}
