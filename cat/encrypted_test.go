package cat_test

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"math"
	"net/netip"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

var encKey = []byte("0123456789abcdef") // a 128-bit test key

// encrypt0 encrypts plaintext as a tagged COSE_Encrypt0 with A128GCM under encKey (decision 0030).
func encrypt0(t *testing.T, plaintext []byte) string {
	t.Helper()
	return encrypt0With(t, enc(t, map[int64]any{1: 1}), plaintext)
}

// encrypt0With is encrypt0 with the protected header bytes given exactly.
func encrypt0With(t *testing.T, protected, plaintext []byte) string {
	t.Helper()
	iv := []byte("twelve-bytes")
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, enc(t, []any{"Encrypt0", protected, []byte{}}))
	return base64.RawURLEncoding.EncodeToString(enc(t, cbor.Tag{Number: 16, Content: []any{protected, map[int64]any{5: iv}, ciphertext}}))
}

func decrypting(v *cat.Validator, issuer string) *cat.Validator {
	v.DecryptionKeys = func([]byte) (cat.Key, error) {
		return cat.Key{Key: cwt.Key{Algorithm: cwt.A128GCM, Material: encKey}, Issuer: issuer}, nil
	}
	return v
}

func TestEncryptedClaimSet(t *testing.T) {
	token := encrypt0(t, enc(t, map[any]any{1: "issuer", 4: 1700000060}))
	tok, err := decrypting(validator(), "issuer").Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !tok.Encrypted || tok.Algorithm != cwt.A128GCM {
		t.Fatalf("Encrypted %v, Algorithm %v", tok.Encrypted, tok.Algorithm)
	}
	if _, err := decrypting(validator(), "someone else").Validate(token); err == nil {
		t.Fatal("an iss that is not the decryption key's issuer was accepted")
	}
	if _, err := validator().Validate(token); !errors.Is(err, cwt.ErrUnsupported) {
		t.Fatalf("without DecryptionKeys: %v", err)
	}
}

func TestEncryptedNestedMessage(t *testing.T) {
	inner := mac0{kid: []byte("k1"), payload: enc(t, map[any]any{1: "issuer", 4: 1700000060})}.bytes(t)
	token := encrypt0(t, inner)
	tok, err := decrypting(validator(), "").Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !tok.Encrypted || tok.Algorithm != cwt.HMAC256x256 || string(tok.KID) != "k1" {
		t.Fatalf("got %+v", tok)
	}
	bad := mac0{kid: []byte("k1"), payload: enc(t, map[any]any{1: "issuer"})}.bytes(t)
	bad[len(bad)-1] ^= 1
	if _, err := decrypting(validator(), "").Validate(encrypt0(t, bad)); !errors.Is(err, cwt.ErrVerification) {
		t.Fatalf("a nested message with a bad MAC: %v", err)
	}
}

func TestEncryptedClaimsLiftLimits(t *testing.T) {
	v := decrypting(validator(), "issuer")
	// "u4pruy" is a prefix of geohash.org's published "u4pruydqqvj" for 57.64911, 10.40744 (see geo_internal_test.go).
	long := map[any]any{1: "issuer", 282: "u4pruy"}
	if _, err := v.ValidateRequest(encrypt0(t, enc(t, long)), atPoint(57.64911, 10.40744)); err != nil {
		t.Fatalf("an encrypted six-character geohash: %v", err)
	}
	if _, err := v.ValidateRequest(claimsToken(t, long), atPoint(57.64911, 10.40744)); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("an unencrypted six-character geohash: %v", err)
	}
	if _, err := v.ValidateRequest(encrypt0(t, enc(t, map[any]any{1: "issuer", 282: "u4pruydqqvj0b"})), atPoint(57.64911, 10.40744)); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("a geohash longer than twelve characters: %v", err)
	}

	address := map[any]any{1: "issuer", 311: []any{cbor.Tag{Number: 52, Content: []byte{192, 0, 2, 1}}}}
	req := get()
	req.ClientIP = netip.MustParseAddr("192.0.2.1")
	if _, err := v.ValidateRequest(encrypt0(t, enc(t, address)), req); err != nil {
		t.Fatalf("an encrypted catnip address: %v", err)
	}
	if _, err := v.ValidateRequest(claimsToken(t, address), req); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("an unencrypted catnip address: %v", err)
	}
}

// TestCatgeocoord checks claim 317 (decision 0030): Paris's centre with a 10 km radius, and a 1 m radius.
func TestCatgeocoord(t *testing.T) {
	v := decrypting(validator(), "issuer")
	paris := encrypt0(t, enc(t, map[any]any{1: "issuer", 317: []any{[]any{48.8566, 2.3522, 10000}}}))
	two := encrypt0(t, enc(t, map[any]any{1: "issuer", 317: []any{[]any{0, 0, 1}, []any{48.8566, 2.3522, 10000}}}))
	cases := []struct {
		name  string
		token string
		req   *cat.Request
		want  error
	}{
		{"inside the circle", paris, atPoint(48.8738, 2.2950), nil},              // about 4.6 km away
		{"outside the circle", paris, atPoint(48.8049, 2.1204), cat.ErrLocation}, // about 18 km away
		{"inside the second of two", two, atPoint(48.86, 2.35), nil},
		{"no coordinates", paris, located("FR", ""), nil},
		{"coordinates that are not a position", paris, atPoint(91, 0), cat.ErrLocation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.ValidateRequest(tc.token, tc.req)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateRequest: %v", err)
				}
				return
			}
			wantKind(t, err, tc.want)
		})
	}
	for name, value := range map[string]any{
		"unencrypted":         nil,
		"not an array":        []any{48.8566, 2.3522, 10000},
		"an empty array":      []any{},
		"two elements":        []any{[]any{48.8566, 2.3522}},
		"a negative radius":   []any{[]any{48.8566, 2.3522, -1}},
		"a text latitude":     []any{[]any{"48", 2.3522, 1}},
		"a latitude above 90": []any{[]any{90.5, 2.3522, 1}},
		"a CRS Wrapper":       cbor.Tag{Number: 279, Content: []any{4326, []any{[]any{48.8566, 2.3522, 1}}}},
	} {
		t.Run(name, func(t *testing.T) {
			var token string
			if value == nil {
				token = claimsToken(t, map[any]any{1: "issuer", 317: []any{[]any{48.8566, 2.3522, 10000}}})
			} else {
				token = encrypt0(t, enc(t, map[any]any{1: "issuer", 317: value}))
			}
			if _, err := v.ValidateRequest(token, atPoint(48.86, 2.35)); !errors.Is(err, cwt.ErrMalformed) {
				t.Fatalf("got %v, want malformed", err)
			}
		})
	}
}

// TestEncryptedTokensAreNotRenewed checks that catr does not renew an encrypted token, whose renewal would carry
// its claims in the clear (decision 0030).
func TestEncryptedTokensAreNotRenewed(t *testing.T) {
	v := decrypting(validator(), "issuer")
	v.Issuance = &cat.Issuance{Issuer: "cdn", Key: func(string) (cwt.SigningKey, error) {
		return cwt.SigningKey{Algorithm: cwt.HMAC256x256, Material: hmacSecret}, nil
	}}
	tok, err := v.Validate(encrypt0(t, enc(t, map[any]any{1: "issuer", 4: 1700000060, 323: map[int64]any{0: 2, 1: 60}})))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	r, err := v.Renew(tok, testNow)
	if r != nil || err != nil {
		t.Fatalf("Renew = %v, %v; want no renewal", r, err)
	}
}

// TestEncryptedProtectedHeaderDeterministic checks that an encrypted token's protected header must be
// deterministically encoded, like a signed one's: here {1: 1} with the key 1 in a two-byte form.
func TestEncryptedProtectedHeaderDeterministic(t *testing.T) {
	token := encrypt0With(t, []byte{0xa1, 0x18, 0x01, 0x01}, enc(t, map[any]any{1: "issuer"}))
	if _, err := decrypting(validator(), "issuer").Validate(token); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("got %v, want malformed", err)
	}
}

// TestEncryptedLimitsExactly checks the edges of the limits encryption lifts (decision 0030).
func TestEncryptedLimitsExactly(t *testing.T) {
	v := decrypting(validator(), "issuer")
	twelve := encrypt0(t, enc(t, map[any]any{1: "issuer", 282: "u4pruydqqvj0"}))
	if _, err := v.ValidateRequest(twelve, atPoint(57.64911, 10.40744)); errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("a twelve-character geohash was refused as malformed: %v", err)
	}

	one := map[any]any{1: "issuer", 311: []any{cbor.Tag{Number: 52, Content: []byte{192, 0, 2, 1}}}}
	neighbour := get()
	neighbour.ClientIP = netip.MustParseAddr("192.0.2.2")
	if _, err := v.ValidateRequest(encrypt0(t, enc(t, one)), neighbour); !errors.Is(err, cat.ErrUnacceptable) {
		t.Fatalf("an address names one host, so its neighbour must be refused: %v", err)
	}
	v6 := map[any]any{1: "issuer", 311: []any{cbor.Tag{Number: 54, Content: netip.MustParseAddr("2001:db8::1").AsSlice()}}}
	req := get()
	req.ClientIP = netip.MustParseAddr("2001:db8::1")
	if _, err := v.ValidateRequest(encrypt0(t, enc(t, v6)), req); err != nil {
		t.Fatalf("an encrypted IPv6 address: %v", err)
	}
	short := map[any]any{1: "issuer", 311: []any{cbor.Tag{Number: 52, Content: []byte{192, 0, 2}}}}
	if _, err := v.ValidateRequest(encrypt0(t, enc(t, short)), req); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("a three-byte IPv4 address: %v", err)
	}
	text := map[any]any{1: "issuer", 311: []any{cbor.Tag{Number: 52, Content: "abcd"}}} // four bytes, as text
	if _, err := v.ValidateRequest(encrypt0(t, enc(t, text)), req); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("an address as text: %v", err)
	}
}

// TestCatgeocoordEdges checks catgeocoord's numbers at their edges (decision 0030).
func TestCatgeocoordEdges(t *testing.T) {
	v := decrypting(validator(), "issuer")
	token := func(loc ...any) string {
		return encrypt0(t, enc(t, map[any]any{1: "issuer", 317: []any{loc}}))
	}
	cases := []struct {
		name  string
		token string
		req   *cat.Request
		want  error
	}{
		{"a radius of zero at the centre itself", token(48.86, 2.35, 0), atPoint(48.86, 2.35), nil},
		{"integer coordinates", token(48, 2, 1000), atPoint(48, 2), nil},
		{"integer coordinates, outside", token(48, 2, 1000), atPoint(48.5, 2), cat.ErrLocation},
		{"a centre at the north pole", token(90, 0, 1000), atPoint(89.999, 0), nil},
		{"a centre at the south-west corner", token(-90, -180, 1000), atPoint(-89.999, -180), nil},
		{"a centre on the antimeridian", token(0, 180, 1000), atPoint(0, 179.999), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.ValidateRequest(tc.token, tc.req)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateRequest: %v", err)
				}
				return
			}
			wantKind(t, err, tc.want)
		})
	}
	for name, loc := range map[string][]any{
		"a latitude below -90":   {-90.5, 0, 1},
		"a longitude above 180":  {0, 180.5, 1},
		"a longitude below -180": {0, -180.5, 1},
		"a latitude that is NaN": {math.NaN(), 0, 1},
		"an infinite longitude":  {0, math.Inf(1), 1},
		"a latitude too big":     {uint64(1) << 63, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.ValidateRequest(token(loc...), atPoint(0, 0)); !errors.Is(err, cwt.ErrMalformed) {
				t.Fatalf("got %v, want malformed", err)
			}
		})
	}
}
