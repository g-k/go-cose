
package cose

import (
	"errors"
)





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
// Per https://tools.ietf.org/html/rfc8152#section-16.4
// should use Tables 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 18, and 20.
func GetAlgTag(label string) (tag int, err error) {
	switch label {

	// Table 5: ECDSA Algorithm Values
	case "ES256":
		return -7, nil
	case "ES384":
		return -35, nil
	case "ES512":
		return -36, nil

	// Table 6: EdDSA Algorithm Values
	case "EdDSA":
		return -8, nil

	// Table 7: HMAC Algorithm Values
	case "HMAC 256/64":
		return 4, nil
	case "HMAC 256/256":
		return 5, nil
   	case "HMAC 384/384":
		return 6, nil
	case "HMAC 512/512":
		return 7, nil

	// Table 8: AES-MAC Algorithm Values
	case "AES-MAC 128/64":
		return 14, nil
	case "AES-MAC 256/64":
		return 15, nil
	case "AES-MAC 128/128":
		return 25, nil
	case "AES-MAC 256/128":
		return 26, nil

	// Table 9: Algorithm Value for AES-GCM
	case "A128GCM":
		return 1, nil
	case "A192GCM":
		return 2, nil
	case "A256GCM":
		return 3, nil

	// TODO: finish tables 10, 11, 15, 16, 17, 18, and 20

	// Table 10: Algorithm Values for AES-CCM
	case "AES-CCM-16-64-128":
		return 10, nil

	default:
		return 0, errors.New("Alg not implemented or invalid.")
	}
}
