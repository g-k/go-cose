
// COSE Algorithms
//

package cose


import (
	"crypto"
)

type COSEAlgorithm struct {
	Name string
	Value int
	HashFunc crypto.Hash // optional hash function for SignMessages
	keySize int // for an ecdsa signature size of r and s in bytes
}

var COSEAlgorithms = []COSEAlgorithm{
	COSEAlgorithm{
		Name: "RSAES-OAEP w/ SHA-512",  // RSAES-OAEP w/ SHA-512 from [RFC8230]
		Value: -42,
	},
	COSEAlgorithm{
		Name: "RSAES-OAEP w/ SHA-256",  // RSAES-OAEP w/ SHA-256 from [RFC8230]
		Value: -41,
	},
	COSEAlgorithm{
		Name: "RSAES-OAEP w/ RFC 8017 default parameters",  // RSAES-OAEP w/ SHA-1 from [RFC8230]
		Value: -40,
	},
	COSEAlgorithm{
		Name: "PS512",  // RSASSA-PSS w/ SHA-512 from [RFC8230]
		Value: -39,
	},
	COSEAlgorithm{
		Name: "PS384",  // RSASSA-PSS w/ SHA-384 from [RFC8230]
		Value: -38,
	},
	COSEAlgorithm{
		Name: "PS256",  // RSASSA-PSS w/ SHA-256 from [RFC8230]
		Value: -37,
		HashFunc: crypto.SHA256,
	},
	COSEAlgorithm{
		Name: "ES512",  // ECDSA w/ SHA-512 from [RFC8152]
		Value: -36,
		HashFunc: crypto.SHA512,
		keySize: 66,
	},
	COSEAlgorithm{
		Name: "ES384",  // ECDSA w/ SHA-384 from [RFC8152]
		Value: -35,
		HashFunc: crypto.SHA384,
		keySize: 48,
	},
	COSEAlgorithm{
		Name: "ECDH-SS + A256KW",  // ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key from [RFC8152]
		Value: -34,
	},
	COSEAlgorithm{
		Name: "ECDH-SS + A192KW",  // ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key from [RFC8152]
		Value: -33,
	},
	COSEAlgorithm{
		Name: "ECDH-SS + A128KW",  // ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key from [RFC8152]
		Value: -32,
	},
	COSEAlgorithm{
		Name: "ECDH-ES + A256KW",  // ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key from [RFC8152]
		Value: -31,
	},
	COSEAlgorithm{
		Name: "ECDH-ES + A192KW",  // ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key from [RFC8152]
		Value: -30,
	},
	COSEAlgorithm{
		Name: "ECDH-ES + A128KW",  // ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key from [RFC8152]
		Value: -29,
	},
	COSEAlgorithm{
		Name: "ECDH-SS + HKDF-512",  // ECDH SS w/ HKDF - generate key directly from [RFC8152]
		Value: -28,
	},
	COSEAlgorithm{
		Name: "ECDH-SS + HKDF-256",  // ECDH SS w/ HKDF - generate key directly from [RFC8152]
		Value: -27,
	},
	COSEAlgorithm{
		Name: "ECDH-ES + HKDF-512",  // ECDH ES w/ HKDF - generate key directly from [RFC8152]
		Value: -26,
	},
	COSEAlgorithm{
		Name: "ECDH-ES + HKDF-256",  // ECDH ES w/ HKDF - generate key directly from [RFC8152]
		Value: -25,
	},
	COSEAlgorithm{
		Name: "direct+HKDF-AES-256",  // Shared secret w/ AES-MAC 256-bit key from [RFC8152]
		Value: -13,
	},
	COSEAlgorithm{
		Name: "direct+HKDF-AES-128",  // Shared secret w/ AES-MAC 128-bit key from [RFC8152]
		Value: -12,
	},
	COSEAlgorithm{
		Name: "direct+HKDF-SHA-512",  // Shared secret w/ HKDF and SHA-512 from [RFC8152]
		Value: -11,
	},
	COSEAlgorithm{
		Name: "direct+HKDF-SHA-256",  // Shared secret w/ HKDF and SHA-256 from [RFC8152]
		Value: -10,
	},
	COSEAlgorithm{
		Name: "EdDSA",  // EdDSA from [RFC8152]
		Value: -8,
	},
	COSEAlgorithm{
		Name: "ES256",  // ECDSA w/ SHA-256 from [RFC8152]
		Value: -7,
		HashFunc: crypto.SHA256,
		keySize: 32,
	},
	COSEAlgorithm{
		Name: "direct",  // Direct use of CEK from [RFC8152]
		Value: -6,
	},
	COSEAlgorithm{
		Name: "A256KW",  // AES Key Wrap w/ 256-bit key from [RFC8152]
		Value: -5,
	},
	COSEAlgorithm{
		Name: "A192KW",  // AES Key Wrap w/ 192-bit key from [RFC8152]
		Value: -4,
	},
	COSEAlgorithm{
		Name: "A128KW",  // AES Key Wrap w/ 128-bit key from [RFC8152]
		Value: -3,
	},
	COSEAlgorithm{
		Name: "A128GCM",  // AES-GCM mode w/ 128-bit key, 128-bit tag from [RFC8152]
		Value: 1,
	},
	COSEAlgorithm{
		Name: "A192GCM",  // AES-GCM mode w/ 192-bit key, 128-bit tag from [RFC8152]
		Value: 2,
	},
	COSEAlgorithm{
		Name: "A256GCM",  // AES-GCM mode w/ 256-bit key, 128-bit tag from [RFC8152]
		Value: 3,
	},
	COSEAlgorithm{
		Name: "HMAC 256/64",  // HMAC w/ SHA-256 truncated to 64 bits from [RFC8152]
		Value: 4,
	},
	COSEAlgorithm{
		Name: "HMAC 256/256",  // HMAC w/ SHA-256 from [RFC8152]
		Value: 5,
	},
	COSEAlgorithm{
		Name: "HMAC 384/384",  // HMAC w/ SHA-384 from [RFC8152]
		Value: 6,
	},
	COSEAlgorithm{
		Name: "HMAC 512/512",  // HMAC w/ SHA-512 from [RFC8152]
		Value: 7,
	},
	COSEAlgorithm{
		Name: "AES-CCM-16-64-128",  // AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce from [RFC8152]
		Value: 10,
	},
	COSEAlgorithm{
		Name: "AES-CCM-16-64-256",  // AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce from [RFC8152]
		Value: 11,
	},
	COSEAlgorithm{
		Name: "AES-CCM-64-64-128",  // AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce from [RFC8152]
		Value: 12,
	},
	COSEAlgorithm{
		Name: "AES-CCM-64-64-256",  // AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce from [RFC8152]
		Value: 13,
	},
	COSEAlgorithm{
		Name: "AES-MAC 128/64",  // AES-MAC 128-bit key, 64-bit tag from [RFC8152]
		Value: 14,
	},
	COSEAlgorithm{
		Name: "AES-MAC 256/64",  // AES-MAC 256-bit key, 64-bit tag from [RFC8152]
		Value: 15,
	},
	COSEAlgorithm{
		Name: "ChaCha20/Poly1305",  // ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag from [RFC8152]
		Value: 24,
	},
	COSEAlgorithm{
		Name: "AES-MAC 128/128",  // AES-MAC 128-bit key, 128-bit tag from [RFC8152]
		Value: 25,
	},
	COSEAlgorithm{
		Name: "AES-MAC 256/128",  // AES-MAC 256-bit key, 128-bit tag from [RFC8152]
		Value: 26,
	},
	COSEAlgorithm{
		Name: "AES-CCM-16-128-128",  // AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce from [RFC8152]
		Value: 30,
	},
	COSEAlgorithm{
		Name: "AES-CCM-16-128-256",  // AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce from [RFC8152]
		Value: 31,
	},
	COSEAlgorithm{
		Name: "AES-CCM-64-128-128",  // AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce from [RFC8152]
		Value: 32,
	},
	COSEAlgorithm{
		Name: "AES-CCM-64-128-256",  // AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce from [RFC8152]
		Value: 33,
	},
}
