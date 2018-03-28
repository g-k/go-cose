package cose

import (
	"os"
	"os/exec"
	"crypto/x509"
	"fmt"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

// signing tests for Firefox Addon COSE Signatures
//

func RustCoseVerifiesGoCoseSignatures(t *testing.T, testCase RustTestCase) {
	fmt.Println(fmt.Sprintf("%s", testCase.Title))

	assert := assert.New(t)
	assert.True(len(testCase.Params) > 0, "No signature params!")

	signers := []Signer{}
	verifiers := []Verifier{}

	var payload = []byte(testCase.SignPayload)
	message := NewSignMessage(payload)
	msgHeaders := NewHeaders(map[interface{}]interface{}{}, map[interface{}]interface{}{})
	msgHeaders.protected[kidTag] = testCase.Certs
	message.SetHeaders(msgHeaders)

	for _, param := range testCase.Params {
		key, err := x509.ParsePKCS8PrivateKey(param.pkcs8)
		assert.Nil(err)

		signer, err := NewSigner(key)
		assert.Nil(err, fmt.Sprintf("%s: Error creating signer %s", testCase.Title, err))
		signers = append(signers, *signer)
		verifiers = append(verifiers, *signer.Verifier(param.algorithm))

		sig := NewSignature()
		sig.headers.protected[algTag] = param.algorithm.Value
		sig.headers.protected[kidTag] = param.certificate

		message.AddSignature(sig)
	}
	assert.True(len(message.signatures) > 0)
	assert.Equal(len(message.signatures), len(signers))

	var external []byte

	err := message.Sign(randReader, external, SignOpts{
		GetSigner: func(index int, signature Signature) (Signer, error) {
			return signers[index], nil
		},
	})
	assert.Nil(err, fmt.Sprintf("%s: signing failed with err %s", testCase.Title, err))

	if testCase.ModifySignature {
		// tamper with the COSE signature.
		sig1 := message.signatures[0].signature
		sig1[len(sig1)-5] ^= sig1[len(sig1)-5]
	}
	if testCase.ModifyPayload {
		message.payload[0] ^= message.payload[0]
	}

	message.payload = nil

	// Verify our signature (round trip)
	err = message.Verify(external, &VerifyOpts{
		GetVerifier: func(index int, signature Signature) (Verifier, error) {
			return verifiers[index], nil
		},
	})

	// encode message and signature
	msgBytes, err := Marshal(message)
	assert.Nil(err, fmt.Sprintf("%s: Error marshaling signed message to bytes %s", testCase.Title, err))

	// fmt.Println(fmt.Sprintf("payload:\n%s\nsig:\n%s\n",
	// 	hex.EncodeToString([]byte(testCase.SignPayload)),
	// 	hex.EncodeToString(msgBytes)))

	// Make sure cose-rust can verify our signature too
	cmd := exec.Command("cargo", "run", "--example", "sign_verify",
		"--",
		"verify",
		hex.EncodeToString([]byte(testCase.SignPayload)),
		hex.EncodeToString(msgBytes))

	cmd.Dir = "./test/cose-rust"
	cmd.Env = append(os.Environ(),
		"NSS_LIB_DIR=/usr/local/opt/nss/lib/",
		"RUSTFLAGS=-A dead_code -A unused_imports",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()

	if testCase.ModifySignature || testCase.ModifyPayload {
		assert.NotNil(err, fmt.Sprintf("%s: verifying signature with cose-rust did not fail %s", testCase.Title, err))
	} else {
		assert.Nil(err, fmt.Sprintf("%s: error verifying signature with cose-rust %s", testCase.Title, err))
	}
}

func TestRustCoseCli(t *testing.T) {
	for _, testCase := range RustTestCases {
		t.Run(testCase.Title, func(t *testing.T) {
			RustCoseVerifiesGoCoseSignatures(t, testCase)
		})
	}
}
