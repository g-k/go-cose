
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
	"github.com/g-k/go-cose/util"
	"github.com/stretchr/testify/assert"
)

func ExpectCastToFail(title string) (shouldFail bool) {
	return title == "sign-pass-03: Remove CBOR Tag" || title == "sign-fail-01: Wrong CBOR Tag"
}

func SignsAndVerifies(t *testing.T, example util.COSEWGExample) {
	assert := assert.New(t)
	privateKey := util.LoadPrivateKey(&example)

	decoded, err := CBORDecode(util.HexToBytesOrDie(example.Output.Cbor))
	assert.Nil(err, fmt.Sprintf("%s: Error decoding example CBOR", example.Title))

	// ugorji/go/codec won't use the Ext to decode without the right CBOR tag
	if ExpectCastToFail(example.Title) {
		return
	}

	msg, ok := decoded.(COSESignMessage)
	assert.True(ok, fmt.Sprintf("%s: Error casting example CBOR to COSESignMessage", example.Title))

	// Test Verify
	ok, err = Verify(&msg, &privateKey.PublicKey, util.HexToBytesOrDie(example.Input.Sign.Signers[0].External))
	if example.Fail {
		assert.False(ok, fmt.Sprintf("%s: verifying signature did not fail", example.Title))
		assert.NotNil(err, fmt.Sprintf("%s: nil error from signature verification failure", example.Title))
		return
	}
	assert.True(ok, fmt.Sprintf("%s: verifying signature failed", example.Title))
	assert.Nil(err, fmt.Sprintf("%s: Error verifying signature", example.Title))

	// Test Sign
	// NB: for the fail test cases, signing should not necessarily
	// fail and the intermediates are wrong
	randReader := rand.New(rand.NewSource(int64(binary.BigEndian.Uint64([]byte(example.Input.RngDescription)))))
	output, err, ToBeSigned := Sign(&msg, &privateKey, randReader, util.HexToBytesOrDie(example.Input.Sign.Signers[0].External))

	// check intermediate
	assert.Equal(example.Intermediates.Signers[0].ToBeSignHex,
		strings.ToUpper(hex.EncodeToString(ToBeSigned)),
		fmt.Sprintf("%s: signing wrong Hex Intermediate", example.Title))

	// check cbor matches (will not match per message keys k match which depend on our RNGs)
	// signed := strings.ToUpper(hex.EncodeToString(CBOREncode(output)))
	// assert.Equal(example.Output.Cbor, signed, "CBOR encoded message wrong")

	// Verify our signature (round trip)
	ok, err = Verify(output, &privateKey.PublicKey, util.HexToBytesOrDie(example.Input.Sign.Signers[0].External))
	assert.Nil(err, fmt.Sprintf("%s: round trip signature verification failed", example.Title))
	assert.True(ok, fmt.Sprintf("%s: round trip error signature verification", example.Title))
}

func TestVerifyWGExamples(t *testing.T) {
	examples := append(
		util.LoadExamples("./test/cose-wg-examples/sign-tests"),
		util.LoadExamples("./test/cose-wg-examples/ecdsa-examples")...)

	for _, example := range examples {
		t.Run(fmt.Sprintf("Example: %s %v", example.Title, example.Fail), func (t *testing.T) {
			SignsAndVerifies(t, example)
		})
	}
}
