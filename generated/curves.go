
// COSE Elliptic Curves
//
// This file is autogenerated modify util/from_csv.go to change it.

package cose

type COSEEllipticCurve struct {
	Name string
	Value int
        KeyType string
}

var COSEEllipticCurves = []COSEEllipticCurve{
	COSEEllipticCurve{
		Name: "P-256",  // NIST P-256 also known as secp256r1 from [RFC8152]
		Value: 1,
                KeyType: "EC2",
	},
	COSEEllipticCurve{
		Name: "P-384",  // NIST P-384 also known as secp384r1 from [RFC8152]
		Value: 2,
                KeyType: "EC2",
	},
	COSEEllipticCurve{
		Name: "P-521",  // NIST P-521 also known as secp521r1 from [RFC8152]
		Value: 3,
                KeyType: "EC2",
	},
	COSEEllipticCurve{
		Name: "X25519",  // X25519 for use w/ ECDH only from [RFC8152]
		Value: 4,
                KeyType: "OKP",
	},
	COSEEllipticCurve{
		Name: "X448",  // X448 for use w/ ECDH only from [RFC8152]
		Value: 5,
                KeyType: "OKP",
	},
	COSEEllipticCurve{
		Name: "Ed25519",  // Ed25519 for use w/ EdDSA only from [RFC8152]
		Value: 6,
                KeyType: "OKP",
	},
	COSEEllipticCurve{
		Name: "Ed448",  // Ed448 for use w/ EdDSA only from [RFC8152]
		Value: 7,
                KeyType: "OKP",
	},
}
