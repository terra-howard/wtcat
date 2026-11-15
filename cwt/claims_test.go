package cwt_test

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

func TestDecodeClaimsKeepsOtherClaimsRaw(t *testing.T) {
	inner := map[string]any{"exact": "/video/"}
	data := encode(t, map[int64]any{1: "issuer", 312: inner})
	c, err := cwt.DecodeClaims(data)
	if err != nil {
		t.Fatalf("DecodeClaims: %v", err)
	}
	if c.Issuer != "issuer" {
		t.Errorf("iss = %q", c.Issuer)
	}
	want := encode(t, inner)
	if !bytes.Equal(c.Other[312], want) {
		t.Errorf("claim 312 = %x, want %x", c.Other[312], want)
	}
	if c.Expiry != nil || c.NotBefore != nil || c.IssuedAt != nil || c.CWTID != nil || c.Subject != "" {
		t.Errorf("absent claims should stay empty: %+v", c)
	}
}

func TestDecodeClaimsAcceptsDatesBeforeTheEpoch(t *testing.T) {
	c, err := cwt.DecodeClaims(encode(t, map[int64]any{4: int64(-100)}))
	if err != nil {
		t.Fatalf("DecodeClaims: %v", err)
	}
	if c.Expiry == nil || c.Expiry.Unix() != -100 || c.Expiry.Fraction() != 0 {
		t.Fatalf("exp = %v, want -100", c.Expiry)
	}
}

func TestDecodeClaimsRejects(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"not CBOR", []byte{0xff, 0x00}, cwt.ErrMalformed},
		{"not a map", encode(t, []int{1, 2}), cwt.ErrMalformed},
		{"trailing bytes", append(encode(t, map[int64]any{1: "a"}), 0x00), cwt.ErrMalformed},
		{"iss not text", encode(t, map[int64]any{1: 7}), cwt.ErrMalformed},
		{"sub not text", encode(t, map[int64]any{2: []byte("x")}), cwt.ErrMalformed},
		{"aud not text", encode(t, map[int64]any{3: true}), cwt.ErrMalformed},
		{"cti not bytes", encode(t, map[int64]any{7: "0b71"}), cwt.ErrMalformed},
		{"exp not a number", encode(t, map[int64]any{4: "soon"}), cwt.ErrMalformed},
		{"exp NaN", fromHex(t, "a104f97e00"), cwt.ErrMalformed},
		{"exp infinity", fromHex(t, "a104f97c00"), cwt.ErrMalformed},
		{"exp floating point beyond int64 seconds", encode(t, map[int64]any{4: 1e19}), cwt.ErrUnsupported},
		{"aud array holding a non-string", encode(t, map[int64]any{3: []any{"a", 1}}), cwt.ErrMalformed},
		{"aud array holding a tagged string", encode(t, map[int64]any{3: []any{cbor.Tag{Number: 32, Content: "a"}}}), cwt.ErrMalformed},
		{"exp too large for int64", encode(t, map[int64]any{4: uint64(math.MaxUint64)}), cwt.ErrMalformed},
		{"exp tagged as a date", encode(t, map[int64]any{4: cbor.Tag{Number: 1, Content: 1444064944}}), cwt.ErrMalformed},
		{"iss tagged", encode(t, map[int64]any{1: cbor.Tag{Number: 32, Content: "coap://as.example.com"}}), cwt.ErrMalformed},
		{"text claim key", encode(t, map[string]any{"iss": "a"}), cwt.ErrUnsupported},
		{"boolean claim key", fromHex(t, "a1f56161"), cwt.ErrMalformed},           // {true: "a"}
		{"duplicate claim key", fromHex(t, "a201616101616262"), cwt.ErrMalformed}, // {1: "a", 1: "bb"}
		{"invalid UTF-8 in iss", fromHex(t, "a10162c328"), cwt.ErrMalformed},      // {1: "\xc3\x28"}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cwt.DecodeClaims(tc.data)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want an error wrapping %v", err, tc.want)
			}
		})
	}
}

// RFC 8392 Section 2 lets a NumericDate be a float of any precision (decision 0016); a non-float simple value is
// malformed.
func TestDecodeClaimsDateEncodings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		data     []byte
		sec      int64
		fraction float64
	}{
		{"half-precision float", fromHex(t, "a104f93c00"), 1, 0},                      // {4: 1.0 as float16}
		{"single-precision float", encode(t, map[int64]any{4: float32(1.5)}), 1, 0.5}, // float32
		{"double-precision float", encode(t, map[int64]any{4: 1444064944.5}), 1444064944, 0.5},
		{"negative float", encode(t, map[int64]any{4: -1.25}), -2, 0.75},
	} {
		c, err := cwt.DecodeClaims(tc.data)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if c.Expiry.Unix() != tc.sec || c.Expiry.Fraction() != tc.fraction {
			t.Errorf("%s: exp = (%d, %v), want (%d, %v)", tc.name, c.Expiry.Unix(), c.Expiry.Fraction(), tc.sec, tc.fraction)
		}
	}
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"true", encode(t, map[int64]any{4: true}), cwt.ErrMalformed},
		{"null", fromHex(t, "a104f6"), cwt.ErrMalformed}, // {4: null}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cwt.DecodeClaims(tc.data); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// Added after Gremlins (task 11). Kills mutants that would apply RFC 8392's no-tags rule beyond the registered claims 1 to 7. Other claims may be
// tagged, and are kept raw.
func TestDecodeClaimsKeepsTaggedUnregisteredClaims(t *testing.T) {
	tagged := cbor.Tag{Number: 32, Content: "https://example.com/"}
	data := encode(t, map[int64]any{-1: tagged, 0: tagged, 8: tagged, 312: tagged})
	c, err := cwt.DecodeClaims(data)
	if err != nil {
		t.Fatalf("DecodeClaims: %v", err)
	}
	want := encode(t, tagged)
	for _, key := range []int64{-1, 0, 8, 312} {
		if !bytes.Equal(c.Other[key], want) {
			t.Errorf("claim %d = %x, want %x", key, c.Other[key], want)
		}
	}
}

// Added after Gremlins (task 11). Kills the boundary mutant of the claim-key range check.
func TestDecodeClaimsKeyAtTheInt64Limit(t *testing.T) {
	c, err := cwt.DecodeClaims(encode(t, map[uint64]any{math.MaxInt64: "x"}))
	if err != nil {
		t.Fatalf("key MaxInt64: %v", err)
	}
	if _, ok := c.Other[math.MaxInt64]; !ok {
		t.Fatal("claim MaxInt64 missing")
	}
	if _, err := cwt.DecodeClaims(encode(t, map[uint64]any{math.MaxInt64 + 1: "x"})); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("key MaxInt64+1: got %v, want ErrMalformed", err)
	}
}

func FuzzDecodeClaims(f *testing.F) {
	seed(f, seedClaimsA1)
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := cwt.DecodeClaims(data)
		checkClassified(t, err, cwt.ErrMalformed, cwt.ErrUnsupported)
		if err == nil && c == nil {
			t.Fatal("nil claims without an error")
		}
	})
}

// RFC 8392 Section 3.1.3 lets aud be a string or an array of strings (decision 0016).
func TestDecodeClaimsAudienceShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		aud  any
		want []string
	}{
		{"a string", "a", []string{"a"}},
		{"an array", []string{"a", "b"}, []string{"a", "b"}},
		{"an empty array", []string{}, []string{}},
	} {
		c, err := cwt.DecodeClaims(encode(t, map[int64]any{3: tc.aud}))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if c.Audience == nil || len(c.Audience) != len(tc.want) {
			t.Errorf("%s: Audience = %#v, want %#v", tc.name, c.Audience, tc.want)
			continue
		}
		for i := range tc.want {
			if c.Audience[i] != tc.want[i] {
				t.Errorf("%s: Audience = %q, want %q", tc.name, c.Audience, tc.want)
			}
		}
	}
}
