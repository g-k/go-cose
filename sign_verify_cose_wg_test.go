
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

	// fmt.Println(fmt.Sprintf("Decoded: %+v", decoded))

	// ugorji/go/codec won't use the Ext to decode without the right CBOR tag
	if ExpectCastToFail(example.Title) {
		return
	}

	msg, ok := decoded.(COSESignMessage)
	assert.True(ok, fmt.Sprintf("%s: Error casting example CBOR to COSESignMessage", example.Title))

	// fmt.Println(fmt.Sprintf("Decoded after cast: %+v", msg))

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
	assert.Nil(err, fmt.Sprintf("%s: signing failed with err %s", example.Title, err))

	// check intermediate
	assert.Equal(example.Intermediates.Signers[0].ToBeSignHex,
		strings.ToUpper(hex.EncodeToString(ToBeSigned)),
		fmt.Sprintf("%s: signing wrong Hex Intermediate", example.Title))

	// check cbor matches (will not match per message keys k match which depend on our RNGs)
	// signed := strings.ToUpper(hex.EncodeToString(CBOREncode(output)))
	// assert.Equal(example.Output.Cbor, signed, "CBOR encoded message wrong")

	// Verify our signature (round trip)
	ok, err = Verify(output, &privateKey.PublicKey, util.HexToBytesOrDie(example.Input.Sign.Signers[0].External))
	assert.Nil(err, fmt.Sprintf("%s: round trip signature verification failed %s", example.Title, err))
	assert.True(ok, fmt.Sprintf("%s: round trip error signature verification", example.Title))
}

var SkipExampleTitles = map[string]bool{
	"ECDSA-01: ECDSA - P-256": false, // ecdsa-01.json
	"ECDSA-02: ECDSA - P-384": false, // ecdsa-02.json

	"ECDSA-03: ECDSA - P-512": false, // ecdsa-03.json

	// not recommended "SHA-256 be used only with curve P-256,
	// SHA-384 be used only with curve P-384, and SHA-512 be used
	// with curve P-521"
	"ECDSA-01: ECDSA - P-256 w/ SHA-512": true, // ecdsa-04.json

	// unsupported message types
	"ECDSA-01: ECDSA - P-256 - sign0": true, // ecdsa-sig-01.json
	"ECDSA-sig-02: ECDSA - P-384 - sign1": true,  // ecdsa-sig-02.json
	"ECDSA-03: ECDSA - P-512 - sign0": true,  // ecdsa-sig-03.json
	"ECDSA-sig-01: ECDSA - P-256 w/ SHA-512 - implicit": true,  // ecdsa-sig-04.json
}

func TestWGExamples(t *testing.T) {
	examples := append(
		util.LoadExamples("./test/cose-wg-examples/sign-tests"),
		util.LoadExamples("./test/cose-wg-examples/ecdsa-examples")...
	)


	for _, example := range examples {
		// fmt.Println(fmt.Sprintf("Example: %+v", example))

		t.Run(fmt.Sprintf("Example: %s %v", example.Title, example.Fail), func (t *testing.T) {
			if v, ok := SkipExampleTitles[example.Title]; ok && v {
				return
			}
			SignsAndVerifies(t, example)
		})
	}
}
