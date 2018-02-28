
package cose

import (
	// "bytes"
	"strings"
	// "crypto"
	"math/rand"
	"fmt"
	"testing"
	"encoding/binary"
	"encoding/hex"
	"github.com/g-k/go-cose/test"
	"github.com/stretchr/testify/assert"
)

func ExpectCastToFail(title string) (shouldFail bool) {
	return title == "sign-pass-03: Remove CBOR Tag" || title == "sign-fail-01: Wrong CBOR Tag"
}

func SignsAndVerifies(t *testing.T, example test.COSEWGExample) {
	assert := assert.New(t)
	privateKey := test.LoadPrivateKey(&example)

	decoded, err := CBORDecode(test.HexToBytesOrDie(example.Output.Cbor))
	assert.Nil(err, fmt.Sprintf("%s: Error decoding example CBOR", example.Title))

	// ugorji/go/codec won't use the ext without a tag
	if ExpectCastToFail(example.Title) {
		return
	}

	msg, ok := decoded.(COSESignMessage)
	assert.True(ok, fmt.Sprintf("%s: Error casting example CBOR to COSESignMessage", example.Title))

	ok, err = Verify(&msg, &privateKey.PublicKey, test.HexToBytesOrDie(example.Input.Sign.Signers[0].External))
	if example.Fail {
		assert.False(ok, fmt.Sprintf("%s: verifying signature did not fail", example.Title))
		assert.NotEqual(nil, err, fmt.Sprintf("%s: no error verifying signature", example.Title))
	} else {
		assert.True(ok, fmt.Sprintf("%s: verifying signature failed", example.Title))
		assert.Nil(err, fmt.Sprintf("%s: Error verifying signature", example.Title))
	}
}

func TestVerifyWGExamples(t *testing.T) {
	for _, example := range test.LoadExamples("./test/cose-wg-examples/sign-tests") {
		t.Run(fmt.Sprintf("Example: %s %v", example.Title, example.Fail), func (t *testing.T) {
			SignsAndVerifies(t, example)
		})
	}
}

func TestSignExtExampleIntermediate(t *testing.T) {
	assert := assert.New(t)
	example := test.LoadExample("./test/cose-wg-examples/sign-tests/sign-pass-02.json")

	privateKey := test.LoadPrivateKey(&example)

	decoded, err := CBORDecode(test.HexToBytesOrDie(example.Output.Cbor))
	assert.Nil(err, "Error decoding example CBOR")

	msg, ok := decoded.(COSESignMessage)
	assert.True(ok, "Error casting example CBOR as COSESignMessage")

	randReader := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64([]byte(example.Input.RngDescription)))))

	_, err, ToBeSigned := Sign(&msg, &privateKey, randReader, test.HexToBytesOrDie(example.Input.Sign.Signers[0].External))
	assert.Nil(err)

	toSign := strings.ToUpper(hex.EncodeToString(ToBeSigned))
	// log.Println(fmt.Printf("ToBeSigned %+v", ToBeSigned))
	assert.Equal(example.Intermediates.Signers[0].ToBeSignHex, toSign, "sig_signature wrong")
}

func TestSignExample(t *testing.T) {
	example := test.LoadExample("./test/cose-wg-examples/sign-tests/sign-pass-01.json")
	// NB: we ignore example.Input.Sign.Protected.Ctyp

	assert := assert.New(t)

	signerInput := example.Input.Sign.Signers[0]

	msgSig := NewCOSESignature()
	msgSig.headers.protected["alg"] = signerInput.Protected.Alg
	msgSig.headers.unprotected["kid"] = signerInput.Unprotected.Kid

	msg := NewCOSESignMessage([]byte(example.Input.Plaintext))
	msg.AddSignature(msgSig)
	// fmt.Println(fmt.Printf("TestSignExample %+v %+v", msgSig.headers.unprotected, msg.signatures[0].headers))

	privateKey := test.LoadPrivateKey(&example)

	// randReader := bytes.NewReader([]byte(example.Input.RngDescription))
	randReader := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64([]byte(example.Input.RngDescription)))))

	output, err, ToBeSigned := Sign(&msg, &privateKey, randReader, test.HexToBytesOrDie(example.Input.Sign.Signers[0].External))
	assert.Nil(err)

	toSign := strings.ToUpper(hex.EncodeToString(ToBeSigned))
	// log.Println(fmt.Printf("ToBeSigned %+v", ToBeSigned))
	assert.Equal(example.Intermediates.Signers[0].ToBeSignHex, toSign, "sig_signature wrong")

	// check cbor matches (will not match per message keys k match which depend on our RNGs)
	// signed := strings.ToUpper(hex.EncodeToString(CBOREncode(output)))
	// assert.Equal(example.Output.Cbor, signed, "CBOR encoded message wrong")

	// Verify our signature (round trip)
	ok, err := Verify(output, &privateKey.PublicKey, test.HexToBytesOrDie(example.Input.Sign.Signers[0].External))
	assert.Nil(err)
	assert.True(ok)
}
