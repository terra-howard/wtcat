package cwt_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

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
