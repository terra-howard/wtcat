package cat_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

func TestValidateAcceptsAndReturnsTheToken(t *testing.T) {
	text := claimsToken(t, map[any]any{
		1: "issuer", 2: "subject", 3: "cdn.example", 4: 1700000060, 5: 1699999940, 6: 1699999940,
		7: []byte{1, 2}, 310: 1,
	})
	tok, err := validator().Validate(text)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if tok.Algorithm != cwt.HMAC256x256 || string(tok.KID) != "k1" {
		t.Errorf("Algorithm, KID = %d, %q", tok.Algorithm, tok.KID)
	}
	c := tok.Claims
	if *c.Issuer != "issuer" || *c.Subject != "subject" || len(c.Audience) != 1 || c.Expiry.Unix() != 1700000060 ||
		c.NotBefore.Unix() != 1699999940 || c.IssuedAt.Unix() != 1699999940 || !bytes.Equal(c.CWTID, []byte{1, 2}) || c.Version != 1 {
		t.Errorf("claims = %+v", c)
	}
}

func TestValidateAcceptsEveryShapeTheSpecificationAllows(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	padded := base64.URLEncoding.EncodeToString(mac0{kid: []byte("k1"), payload: enc(t, map[any]any{})}.bytes(t))
	cases := []struct {
		name string
		text string
		v    *cat.Validator
	}{
		{"padded text", padded, validator()},
		{"no alg and no kid, as in the specification's own HMAC example", mac0{protected: []byte{}, payload: enc(t, map[any]any{4: 1700000060})}.text(t), validator()},
		{"empty claim set", claimsToken(t, map[any]any{}), validator()},
		{"aud as an array naming this recipient", claimsToken(t, map[any]any{3: []string{"other", "cdn.example"}}), validator()},
		{"floating-point exp", claimsToken(t, map[any]any{4: 1700000000.5}), validator()},
		{"unknown and optional claims", claimsToken(t, map[any]any{"x": 1, -1: 2, 308: 1, 322: map[any]any{}}), validator()},
		{"ES256", es256Text(t, ecKey, map[any]any{1: "es-issuer"}), &cat.Validator{
			Keys: func([]byte) (cat.Key, error) {
				return cat.Key{Key: cwt.Key{Algorithm: cwt.ES256, Material: &ecKey.PublicKey}, Issuer: "es-issuer"}, nil
			},
			Now: func() time.Time { return testNow },
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.v.Validate(tc.text); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestValidatePassesTheKIDToKeys(t *testing.T) {
	var asked [][]byte
	v := validator()
	v.Keys = keys(&asked)
	if _, err := v.Validate(claimsToken(t, map[any]any{})); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(mac0{payload: enc(t, map[any]any{})}.text(t)); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 2 || string(asked[0]) != "k1" || asked[1] != nil {
		t.Errorf("Keys was asked for %q, want k1 then nil", asked)
	}
}

// No leeway: exactly at exp is too late, and a nanosecond before nbf is too early (sections 4.6.3 and 4.6.4).
func TestValidateChecksTimeWithNoLeeway(t *testing.T) {
	integer := claimsToken(t, map[any]any{4: 1700000060, 5: 1699999940})
	fractional := claimsToken(t, map[any]any{4: 1700000060.5, 5: 1699999940.25})
	cases := []struct {
		name string
		text string
		now  time.Time
		want error
	}{
		{"exp, a nanosecond before", integer, time.Unix(1700000059, 999999999), nil},
		{"exp, exactly", integer, time.Unix(1700000060, 0), cat.ErrExpired},
		{"nbf, exactly", integer, time.Unix(1699999940, 0), nil},
		{"nbf, a nanosecond before", integer, time.Unix(1699999939, 999999999), cat.ErrNotYetValid},
		{"fractional exp, a nanosecond before", fractional, time.Unix(1700000060, 499999999), nil},
		{"fractional exp, exactly", fractional, time.Unix(1700000060, 500000000), cat.ErrExpired},
		{"fractional nbf, exactly", fractional, time.Unix(1699999940, 250000000), nil},
		{"fractional nbf, a nanosecond before", fractional, time.Unix(1699999940, 249999999), cat.ErrNotYetValid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := at(validator(), tc.now).Validate(tc.text)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			wantKind(t, err, tc.want)
			wantKind(t, err, cat.ErrUnacceptable)
		})
	}
}

func TestValidateChecksIssuerAndAudience(t *testing.T) {
	noIssuerKey := func([]byte) (cat.Key, error) {
		return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: hmacSecret}}, nil
	}
	noAudiences := validator()
	noAudiences.Audiences = nil
	cases := []struct {
		name   string
		claims map[any]any
		keys   cat.KeyFunc
		v      *cat.Validator
		want   error
	}{
		{"iss of another issuer", map[any]any{1: "someone else"}, nil, validator(), cat.ErrIssuer},
		{"iss with a key tied to no issuer", map[any]any{1: "issuer"}, noIssuerKey, validator(), cat.ErrIssuer},
		{"empty iss with a key tied to no issuer", map[any]any{1: ""}, noIssuerKey, validator(), cat.ErrIssuer},
		{"no iss with a key tied to no issuer", map[any]any{}, noIssuerKey, validator(), nil},
		{"aud naming another recipient", map[any]any{3: "elsewhere.example"}, nil, validator(), cat.ErrAudience},
		{"aud as an empty array", map[any]any{3: []string{}}, nil, validator(), cat.ErrAudience},
		{"aud present, recipient answers to nothing", map[any]any{3: "cdn.example"}, nil, noAudiences, cat.ErrAudience},
		{"no aud, recipient answers to nothing", map[any]any{}, nil, noAudiences, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.keys != nil {
				tc.v.Keys = tc.keys
			}
			_, err := tc.v.Validate(claimsToken(t, tc.claims))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			wantKind(t, err, tc.want)
			wantKind(t, err, cat.ErrUnacceptable)
		})
	}
}

func TestValidateRejectsInvalidTokens(t *testing.T) {
	valid := mac0{kid: []byte("k1"), payload: enc(t, map[any]any{1: "issuer"})}.bytes(t)
	tampered := bytes.Clone(valid)
	tampered[len(tampered)-1] ^= 1
	// The unprotected header is outside the MAC, so re-encoding its map head (a1) in a longer form (b801)
	// leaves the MAC valid; only the deterministic-encoding check of the whole token catches it.
	longMap := bytes.Replace(valid, []byte{0x05, 0xa1}, []byte{0x05, 0xb8, 0x01}, 1)
	b64 := base64.RawURLEncoding.EncodeToString
	cases := []struct {
		name string
		text string
		want error
	}{
		{"not base64url", "0YRD+oQEF", cwt.ErrMalformed},
		{"a header map not in its shortest form", b64(longMap), cwt.ErrMalformed},
		{"a protected header not in its shortest form", mac0{protected: fromHex(t, "a1 01 1805"), payload: enc(t, map[any]any{})}.text(t), cwt.ErrMalformed},
		{"a claim set not in its shortest form", mac0{payload: fromHex(t, "a1 04 1a000003e8")}.text(t), cwt.ErrMalformed},
		{"an integral date encoded as a float", mac0{payload: fromHex(t, "a1 04 fb41d954fc40000000")}.text(t), cwt.ErrMalformed},
		{"an indefinite-length claim set", mac0{payload: fromHex(t, "bf 04 1a6553f13c ff")}.text(t), cwt.ErrMalformed},
		{"a MAC that does not verify", b64(tampered), cwt.ErrVerification},
		{"an unknown kid", mac0{kid: []byte("k2"), payload: enc(t, map[any]any{})}.text(t), cwt.ErrVerification},
		{"cnf, not yet enforced", claimsToken(t, map[any]any{8: map[any]any{}}), cwt.ErrUnsupported},
		{"catv 2", claimsToken(t, map[any]any{310: 2}), cwt.ErrUnsupported},
		{"a tagged claim", mac0{payload: fromHex(t, "a1 01 c0 6161")}.text(t), cwt.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := validator().Validate(tc.text)
			wantKind(t, err, tc.want)
			if errors.Is(err, cat.ErrUnacceptable) {
				t.Errorf("an invalid token's error also wraps cat.ErrUnacceptable")
			}
			if tok != nil {
				t.Errorf("got a token along with the error")
			}
		})
	}
}

func TestValidateLengthLimit(t *testing.T) {
	v := validator()
	wantKind(t, func() error { _, err := v.Validate(strings.Repeat("A", 8193)); return err }(), cwt.ErrUnsupported)
	// Under the default limit of 8192, a long token is read, so garbage is malformed rather than too long.
	wantKind(t, func() error { _, err := v.Validate(strings.Repeat("A", 8192)); return err }(), cwt.ErrMalformed)
	v.MaxLength = 5000
	wantKind(t, func() error { _, err := v.Validate(strings.Repeat("A", 5004)); return err }(), cwt.ErrUnsupported)
}

func TestValidatorConfigurationErrors(t *testing.T) {
	text := claimsToken(t, map[any]any{})
	for name, v := range map[string]*cat.Validator{
		"no key function":           {},
		"a length limit below 4096": {Keys: keys(nil), MaxLength: 4095},
		"a negative length limit":   {Keys: keys(nil), MaxLength: -1},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Validate(text)
			if err == nil {
				t.Fatal("got nil error")
			}
			for _, kind := range []error{cwt.ErrMalformed, cwt.ErrVerification, cwt.ErrUnsupported, cat.ErrUnacceptable} {
				if errors.Is(err, kind) {
					t.Fatalf("a configuration error wraps %v", kind)
				}
			}
		})
	}
	if _, err := (&cat.Validator{Keys: keys(nil), MaxLength: 4096, Now: func() time.Time { return testNow }}).Validate(text); err != nil {
		t.Errorf("a limit of exactly 4096: %v", err)
	}
}

func FuzzValidate(f *testing.F) {
	f.Add("0YRDoQEFoQRCazGhAWZpc3N1ZXJYIEp4")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		tok, err := validator().Validate(text)
		if err == nil {
			if tok == nil {
				t.Fatal("nil token with nil error")
			}
			return
		}
		for _, kind := range []error{cwt.ErrMalformed, cwt.ErrVerification, cwt.ErrUnsupported, cat.ErrUnacceptable} {
			if errors.Is(err, kind) {
				return
			}
		}
		t.Fatalf("unclassified error: %v", err)
	})
}
