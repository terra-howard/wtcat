package cat_test

import (
	"errors"
	"fmt"
	"time"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

func ExampleValidator() {
	secret := []byte("0123456789abcdef0123456789abcdef")
	v := &cat.Validator{
		// Each key is bound to one algorithm and one issuer.
		Keys: func(kid []byte) (cat.Key, error) {
			if string(kid) != "k1" {
				return cat.Key{}, errors.New("unknown key")
			}
			return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: secret}, Issuer: "issuer.example"}, nil
		},
		Audiences: []string{"cdn.example"},
		Now:       func() time.Time { return time.Unix(1700000000, 0) }, // omit to use the real clock
	}

	// An HMAC 256/256 CAT with kid "k1": iss "issuer.example", aud "cdn.example", exp 1700000060.
	const token = "0YRDoQEFoQRCazFYJKMBbmlzc3Vlci5leGFtcGxlA2tjZG4uZXhhbXBsZQQaZVPxPFgg972-1vAC-sLp9wNOdXNbY9ZZO5kotOWeYUItZoQPPiM"

	tok, err := v.Validate(token)
	if err != nil {
		fmt.Println("refused:", err)
		return
	}
	fmt.Println(*tok.Claims.Issuer, tok.Claims.Expiry.Unix())

	v.Now = func() time.Time { return time.Unix(1700000060, 0) }
	_, err = v.Validate(token)
	fmt.Println(errors.Is(err, cat.ErrExpired), errors.Is(err, cat.ErrUnacceptable))
	// Output:
	// issuer.example 1700000060
	// true true
}
