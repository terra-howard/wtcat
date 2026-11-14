package cwt_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("encoding test input: %v", err)
	}
	return b
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test hex: %v", err)
	}
	return b
}

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
	if c.Expiry == nil || *c.Expiry != -100 {
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
		{"exp floating point", encode(t, map[int64]any{4: 1444064944.5}), cwt.ErrUnsupported},
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
