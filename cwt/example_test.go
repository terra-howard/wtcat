package cwt_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

// Verify a MACed CWT, here RFC 8392's example token from Appendix A.4, with an allow-list of algorithms, a key
// lookup by kid, and a clock. The clock is fixed inside the example token's validity window, which ended in 2015.
func ExampleVerifier() {
	token, _ := hex.DecodeString(seedMacedA4)
	secret, _ := hex.DecodeString(keyA22)

	v := &cwt.Verifier{
		Algorithms: []cwt.Algorithm{cwt.HMAC256x64},
		Key: func(kid []byte, alg cwt.Algorithm) (any, error) {
			if string(kid) == "Symmetric256" {
				return secret, nil
			}
			return nil, errors.New("unknown key")
		},
		Now:    func() time.Time { return time.Unix(1443944944+60, 0) },
		Leeway: 30 * time.Second,
	}

	claims, err := v.Verify(token)
	switch {
	case errors.Is(err, cwt.ErrExpired), errors.Is(err, cwt.ErrNotYetValid):
		fmt.Println("outside its validity window")
	case errors.Is(err, cwt.ErrVerification):
		fmt.Println("not authentic")
	case err != nil:
		fmt.Println("rejected:", err)
	default:
		fmt.Println(claims.Issuer, claims.Subject)
	}
	// Output: coap://as.example.com erikw
}

// Issue a MACed CWT, then verify it with the same secret bound to its algorithm. The claim set is any CBOR map
// with integer keys; here iss (1) and exp (4).
func ExampleIssue() {
	secret := []byte("0123456789abcdef0123456789abcdef")
	payload, err := cbor.Marshal(map[int64]any{1: "issuer.example", 4: 1700000060})
	if err != nil {
		fmt.Println(err)
		return
	}

	token, err := cwt.Issue(payload, cwt.SigningKey{Algorithm: cwt.HMAC256x256, KID: []byte("k1"), Material: secret})
	if err != nil {
		fmt.Println("not issued:", err)
		return
	}

	msg, err := cwt.VerifyMessage(token, func(kid []byte) (cwt.Key, error) {
		if string(kid) != "k1" {
			return cwt.Key{}, errors.New("unknown key")
		}
		return cwt.Key{Algorithm: cwt.HMAC256x256, Material: secret}, nil
	})
	if err != nil {
		fmt.Println("refused:", err)
		return
	}
	claims, err := cwt.DecodeClaims(msg.Payload)
	if err != nil {
		fmt.Println("refused:", err)
		return
	}
	fmt.Println(msg.Algorithm, string(msg.KID), claims.Issuer, claims.Expiry.Unix())
	// Output: HMAC 256/256 k1 issuer.example 1700000060
}
