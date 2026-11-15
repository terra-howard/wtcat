package cat

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

func enc(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("encoding test input: %v", err)
	}
	return b
}

// raw is a claim value given as its exact CBOR encoding.
func raw(t *testing.T, hexValue string) cbor.RawMessage { return cbor.RawMessage(mustHex(t, hexValue)) }

func TestDecodeClaimsRFC8392A1(t *testing.T) {
	c, err := decodeClaims(mustHex(t, rfcClaimsA1))
	if err != nil {
		t.Fatalf("decodeClaims: %v", err)
	}
	if c.Issuer == nil || *c.Issuer != "coap://as.example.com" {
		t.Errorf("Issuer = %v", c.Issuer)
	}
	if c.Subject == nil || *c.Subject != "erikw" {
		t.Errorf("Subject = %v", c.Subject)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "coap://light.example.com" {
		t.Errorf("Audience = %q", c.Audience)
	}
	for name, tc := range map[string]struct {
		got  *NumericDate
		want int64
	}{"exp": {c.Expiry, 1444064944}, "nbf": {c.NotBefore, 1443944944}, "iat": {c.IssuedAt, 1443944944}} {
		if tc.got == nil || tc.got.Unix() != tc.want || tc.got.Fraction() != 0 {
			t.Errorf("%s = %v, want %d", name, tc.got, tc.want)
		}
	}
	if !bytes.Equal(c.CWTID, []byte{0x0b, 0x71}) {
		t.Errorf("CWTID = %x", c.CWTID)
	}
	if c.Version != 1 {
		t.Errorf("Version = %d, want 1 when catv is absent", c.Version)
	}
}

func TestDecodeClaimsShapes(t *testing.T) {
	t.Run("empty claims set", func(t *testing.T) {
		c, err := decodeClaims(enc(t, map[int64]any{}))
		if err != nil {
			t.Fatal(err)
		}
		if c.Issuer != nil || c.Subject != nil || c.Audience != nil || c.Expiry != nil || c.NotBefore != nil ||
			c.IssuedAt != nil || c.CWTID != nil || c.Version != 1 || c.Methods != nil {
			t.Errorf("claims = %+v, want every claim absent and Version 1", c)
		}
	})
	t.Run("aud as an array", func(t *testing.T) {
		c, err := decodeClaims(enc(t, map[int64]any{3: []string{"a", "b"}}))
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Audience) != 2 || c.Audience[0] != "a" || c.Audience[1] != "b" {
			t.Errorf("Audience = %q", c.Audience)
		}
	})
	t.Run("aud as an empty array", func(t *testing.T) {
		c, err := decodeClaims(enc(t, map[int64]any{3: []string{}}))
		if err != nil {
			t.Fatal(err)
		}
		if c.Audience == nil || len(c.Audience) != 0 {
			t.Errorf("Audience = %#v, want a non-nil empty slice", c.Audience)
		}
	})
	t.Run("empty cti", func(t *testing.T) {
		c, err := decodeClaims(enc(t, map[int64]any{7: []byte{}}))
		if err != nil {
			t.Fatal(err)
		}
		if c.CWTID == nil || len(c.CWTID) != 0 {
			t.Errorf("CWTID = %#v, want a non-nil empty slice", c.CWTID)
		}
	})
	t.Run("catm", func(t *testing.T) {
		c, err := decodeClaims(enc(t, map[int64]any{313: []string{"GET", "HEAD"}}))
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Methods) != 2 || c.Methods[0] != "GET" || c.Methods[1] != "HEAD" {
			t.Errorf("Methods = %q", c.Methods)
		}
	})
	t.Run("catv 1", func(t *testing.T) {
		c, err := decodeClaims(enc(t, map[int64]any{310: 1}))
		if err != nil || c.Version != 1 {
			t.Fatalf("claims = %+v, err = %v", c, err)
		}
	})
	t.Run("floating-point and extreme dates", func(t *testing.T) {
		c, err := decodeClaims(enc(t, map[int64]any{4: 1700000000.5, 5: -1.5, 6: int64(math.MinInt64)}))
		if err != nil {
			t.Fatal(err)
		}
		if c.Expiry.Unix() != 1700000000 || c.Expiry.Fraction() != 0.5 {
			t.Errorf("exp = (%d, %v)", c.Expiry.Unix(), c.Expiry.Fraction())
		}
		if c.NotBefore.Unix() != -2 || c.NotBefore.Fraction() != 0.5 {
			t.Errorf("nbf = (%d, %v)", c.NotBefore.Unix(), c.NotBefore.Fraction())
		}
		if c.IssuedAt.Unix() != math.MinInt64 {
			t.Errorf("iat = %d", c.IssuedAt.Unix())
		}
		c, err = decodeClaims(enc(t, map[int64]any{4: int64(math.MaxInt64)}))
		if err != nil || c.Expiry.Unix() != math.MaxInt64 {
			t.Errorf("exp MaxInt64: claims = %+v, err = %v", c, err)
		}
	})
}

// Claims a recipient does not understand are ignored (CTA-5007-B sections 4.3.1.5 and 4.5), whatever their key
// or value, and so are the optional claims phase 1 does not support.
func TestDecodeClaimsIgnoresUnknownAndOptionalClaims(t *testing.T) {
	claims := map[any]any{
		"private":         cbor.Tag{Number: 1, Content: 0},
		int64(-7):         raw(t, "c11a00000000"),
		int64(999):        []any{1, "x"},
		uint64(1<<64 - 1): 0,
		int64(308):        1,           // catreplay
		int64(309):        []any{},     // catpor
		int64(314):        "h2",        // catalpn, even with the wrong type
		int64(316):        []any{"CA"}, // catgeoiso3166
		int64(322):        map[int64]any{},
		int64(323):        map[int64]any{},
		int64(1):          "issuer",
	}
	c, err := decodeClaims(enc(t, claims))
	if err != nil {
		t.Fatalf("decodeClaims: %v", err)
	}
	if c.Issuer == nil || *c.Issuer != "issuer" {
		t.Errorf("Issuer = %v", c.Issuer)
	}
}

// Map order is random in Go, so this decodes the same claim set many times: a text-keyed claim must never stop
// the claims after it from being checked.
func TestDecodeClaimsKeepsCheckingAfterATextKey(t *testing.T) {
	claims := map[any]any{int64(8): map[int64]any{}}
	for _, k := range "abcdefghijklmnopqrst" {
		claims[string(k)] = 0
	}
	payload := enc(t, claims)
	for i := 0; i < 30; i++ {
		if _, err := decodeClaims(payload); !errors.Is(err, cwt.ErrUnsupported) {
			t.Fatalf("decode %d: got %v, want cnf refused as unsupported", i, err)
		}
	}
}

func TestDecodeClaimsHalfAndSinglePrecisionDates(t *testing.T) {
	c, err := decodeClaims(mustHex(t, "a2 04 f93800 05 fa3fc00000")) // exp 0.5 as half, nbf 1.5 as single
	if err != nil {
		t.Fatal(err)
	}
	if c.Expiry.Unix() != 0 || c.Expiry.Fraction() != 0.5 || c.NotBefore.Unix() != 1 || c.NotBefore.Fraction() != 0.5 {
		t.Errorf("exp = (%d, %v), nbf = (%d, %v)", c.Expiry.Unix(), c.Expiry.Fraction(), c.NotBefore.Unix(), c.NotBefore.Fraction())
	}
}

func TestDecodeClaimsRejectsMalformed(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"not CBOR", []byte{0xff}},
		{"an array, not a map", enc(t, []any{1})},
		{"a duplicate claim", mustHex(t, "a2 01 6161 01 6162")},
		{"a byte string claim key", mustHex(t, "a1 4100 00")},
		{"iss not text", enc(t, map[int64]any{1: 5})},
		{"iss tagged", enc(t, map[int64]any{1: raw(t, "c06161")})},
		{"sub not text", enc(t, map[int64]any{2: []byte("x")})},
		{"aud an integer", enc(t, map[int64]any{3: 1})},
		{"aud array holding an integer", enc(t, map[int64]any{3: []any{"a", 1}})},
		{"aud array holding a tagged string", enc(t, map[int64]any{3: []any{raw(t, "d8206161")}})},
		{"aud array tagged", enc(t, map[int64]any{3: raw(t, "d829816161")})},
		{"exp text", enc(t, map[int64]any{4: "tomorrow"})},
		{"exp tagged", enc(t, map[int64]any{4: raw(t, "c11a6553f100")})},
		{"exp NaN", enc(t, map[int64]any{4: raw(t, "f97e00")})},
		{"exp infinity", enc(t, map[int64]any{4: raw(t, "f97c00")})},
		{"nbf negative infinity", enc(t, map[int64]any{5: raw(t, "f9fc00")})},
		{"iat a byte string", enc(t, map[int64]any{6: []byte{1}})},
		{"exp a simple value", enc(t, map[int64]any{4: true})},
		{"cti text", enc(t, map[int64]any{7: "id"})},
		{"cti tagged", enc(t, map[int64]any{7: raw(t, "d8184101")})},
		{"catv text", enc(t, map[int64]any{310: "1"})},
		{"catv negative", enc(t, map[int64]any{310: -1})},
		{"catv tagged", enc(t, map[int64]any{310: raw(t, "d903e801")})},
		{"catm not an array", enc(t, map[int64]any{313: "GET"})},
		{"catu not a map", enc(t, map[int64]any{312: []any{}})},
		{"catu with a text component key", enc(t, map[int64]any{312: map[string]any{"path": map[int64]any{}}})},
		{"catu tagged", enc(t, map[int64]any{312: raw(t, "d903e8a0")})},
		{"catu with a malformed match", enc(t, map[int64]any{312: map[int64]any{3: map[int64]any{0: 1}}})},
		{"catm empty", enc(t, map[int64]any{313: []string{}})},
		{"catm holding a non-string", enc(t, map[int64]any{313: []any{"GET", 1}})},
		{"catm holding a tagged string", enc(t, map[int64]any{313: []any{raw(t, "d903e863474554")}})},
		{"catm tagged", enc(t, map[int64]any{313: raw(t, "d9010281634745 54")})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeClaims(tc.payload); !errors.Is(err, cwt.ErrMalformed) {
				t.Fatalf("got %v, want an error wrapping cwt.ErrMalformed", err)
			}
		})
	}
}

func TestDecodeClaimsRefusesUnsupported(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"a nested CWT", enc(t, cbor.Tag{Number: 17, Content: []any{}})},
		{"catv 2", enc(t, map[int64]any{310: 2})},
		{"exp beyond 64-bit seconds", enc(t, map[int64]any{4: uint64(1 << 63)})},
		{"nbf before 64-bit seconds", enc(t, map[int64]any{5: raw(t, "3b8000000000000000")})},
		{"exp as a float beyond 64-bit seconds", enc(t, map[int64]any{4: 1e19})},
		{"nbf as a float before 64-bit seconds", enc(t, map[int64]any{5: -1e19})},
		{"cnf, not yet enforced", enc(t, map[int64]any{8: map[int64]any{}})},
		{"catdpop, not yet enforced", enc(t, map[int64]any{321: map[int64]any{}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeClaims(tc.payload); !errors.Is(err, cwt.ErrUnsupported) {
				t.Fatalf("got %v, want an error wrapping cwt.ErrUnsupported", err)
			}
		})
	}
}

func FuzzDecodeClaims(f *testing.F) {
	f.Add(mustHex(f, rfcClaimsA1))
	seed, err := cbor.Marshal(map[int64]any{3: []string{"a", "b"}, 4: 1700000000.5, 5: -1.5, 310: 1, 999: "x"})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	seed, err = cbor.Marshal(map[int64]any{311: []any{uint64(64500), cbor.Tag{Number: 52, Content: []any{24, []byte{192, 0, 2}}},
		cbor.Tag{Number: 54, Content: []any{32, []byte{0x20, 0x01, 0x0d, 0xb8}}}}, 312: map[int64]any{3: map[int64]any{1: "/a/"}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	seed, err = cbor.Marshal(map[int64]any{313: []string{"GET"}, 315: map[string]any{
		"Accept": map[int64]any{0: "a", 4: []any{"(a|ab)[[:digit:]]", "ab", nil}, -1: []byte{1}},
	}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, payload []byte) {
		c, err := decodeClaims(payload)
		if err != nil {
			if !errors.Is(err, cwt.ErrMalformed) && !errors.Is(err, cwt.ErrUnsupported) {
				t.Fatalf("unclassified error: %v", err)
			}
			return
		}
		if c == nil {
			t.Fatal("nil claims with nil error")
		}
		for _, d := range []*NumericDate{c.Expiry, c.NotBefore, c.IssuedAt} {
			if d != nil && !(d.frac >= 0 && d.frac < 1) {
				t.Fatalf("fraction %v is outside [0, 1)", d.frac)
			}
		}
	})
}
