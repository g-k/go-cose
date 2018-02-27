
package test


import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"path/filepath"
)

// CoseWGExample
// autogenerated from pass and fail examples on https://mholt.github.io/json-to-go/
// then combined (added .Fail and .Input.Failures)
type CoseWGExample struct {
	Title string `json:"title"`
	Fail  bool   `json:"fail"`
	Input struct {
		Plaintext string `json:"plaintext"`
		Sign      struct {
			Protected struct {
				Ctyp int `json:"ctyp"`
			} `json:"protected"`
			Signers []struct {
				Key struct {
					Kty string `json:"kty"`
					Kid string `json:"kid"`
					Crv string `json:"crv"`
					X   string `json:"x"`
					Y   string `json:"y"`
					D   string `json:"d"`
				} `json:"key"`
				Unprotected struct {
					Kid string `json:"kid"`
				} `json:"unprotected"`
				Protected struct {
					Alg string `json:"alg"`
				} `json:"protected"`
			} `json:"signers"`
		} `json:"sign"`
		Failures struct {
			ChangeCBORTag int `json:"ChangeCBORTag"`
		} `json:"failures"`
		RngDescription string `json:"rng_description"`
	} `json:"input"`
	Intermediates struct {
		Signers []struct {
			ToBeSignHex string `json:"ToBeSign_hex"`
		} `json:"signers"`
	} `json:"intermediates"`
	Output struct {
		CborDiag string `json:"cbor_diag"`
		Cbor     string `json:"cbor"`
	} `json:"output"`
}

// https://github.com/square/go-jose/blob/789a4c4bd4c118f7564954f441b29c153ccd6a96/utils_test.go#L45
// Build big int from base64-encoded string.
func FromBase64Int(data string) *big.Int {
	val, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		panic("Invalid test data")
	}
	return new(big.Int).SetBytes(val)
}


func HexToBytesOrDie(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("Error decoding hex string: %s", err))
	}
	return b
}


func LoadExample(path string) CoseWGExample {
	var content, err = ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	var example CoseWGExample
	err = json.Unmarshal(content, &example)
	if err != nil {
		log.Fatal(err)
	}
	return example
}

// LoadExamples
func LoadExamples(path string) []CoseWGExample {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}

	examples := make([]CoseWGExample, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		var content, err = ioutil.ReadFile(filepath.Join(path, file.Name()))
		if err != nil {
			log.Fatal(err)
		}

		var example CoseWGExample
		err = json.Unmarshal(content, &example)
		if err != nil {
			log.Fatal(err)
		}
		examples = append(examples, example)
	}
	return examples
}
