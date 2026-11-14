package cwt_test

// Tests added after Gremlins (decision 0013, task 11) found mutants that no test noticed. Each names the mutant it
// exists to kill.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

// Kills negations of the half and single precision comparisons in isFloat, and confirms a non-float simple value
// in a date is malformed rather than unsupported.
func TestDecodeClaimsDateEncodings(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"half-precision float", fromHex(t, "a104f93c00"), cwt.ErrUnsupported},                    // {4: 1.0 as float16}
		{"single-precision float", encode(t, map[int64]any{4: float32(1.5)}), cwt.ErrUnsupported}, // float32
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

// Kills mutants that would apply RFC 8392's no-tags rule beyond the registered claims 1 to 7. Other claims may be
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

// Kills the boundary mutant of the claim-key range check.
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

// Kills the boundary mutant on the payload length check, which would index an empty payload and panic.
func TestVerifyMac0RejectsAnEmptyPayload(t *testing.T) {
	m := defaultMac0(t)
	m.payload = []byte{}
	if _, err := cwt.VerifyMac0(m.build(t), testKey); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

// Covers the payload type check, which no test reached.
func TestVerifyMac0RejectsANonBytePayload(t *testing.T) {
	m := defaultMac0(t)
	m.payload = map[int64]any{1: "issuer"} // a map where a byte string belongs
	if _, err := cwt.VerifyMac0(m.build(t), testKey); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

// Kills mutants that would let a typed nil key through to a nil dereference.
func TestVerifySign1RejectsTypedNilKeys(t *testing.T) {
	es256 := mustHexBytes(t, seedSignedA3)
	if _, err := cwt.VerifySign1(es256, (*ecdsa.PublicKey)(nil)); !errors.Is(err, cwt.ErrVerification) {
		t.Fatalf("typed nil ECDSA key: got %v, want ErrVerification", err)
	}
	ps256 := encode(t, cbor.Tag{Number: 18, Content: []any{encode(t, map[int64]any{1: -37}), map[int64]any{}, encode(t, map[int64]any{1: "x"}), make([]byte, 256)}})
	if _, err := cwt.VerifySign1(ps256, (*rsa.PublicKey)(nil)); !errors.Is(err, cwt.ErrVerification) {
		t.Fatalf("typed nil RSA key: got %v, want ErrVerification", err)
	}
}

// Covers the Verifier's rejection of a tag that is neither COSE_Mac0 nor COSE_Sign1.
func TestVerifierRejectsAForeignCOSETag(t *testing.T) {
	m := defaultMac0(t)
	m.coseTag = 98 // COSE_Sign
	v := &cwt.Verifier{
		Algorithms: []cwt.Algorithm{cwt.HMAC256x256},
		Key:        func([]byte, cwt.Algorithm) (any, error) { return testKey, nil },
	}
	if _, err := v.Verify(m.build(t)); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

// Covers the Verifier's refusal of an allowed algorithm it cannot verify.
func TestVerifierRefusesAnAllowedButUnknownAlgorithm(t *testing.T) {
	m := defaultMac0(t)
	m.protectedRaw = encode(t, map[int64]any{1: 4242})
	called := false
	v := &cwt.Verifier{
		Algorithms: []cwt.Algorithm{cwt.Algorithm(4242)},
		Key:        func([]byte, cwt.Algorithm) (any, error) { called = true; return testKey, nil },
	}
	if _, err := v.Verify(m.build(t)); !errors.Is(err, cwt.ErrUnsupported) {
		t.Fatalf("got %v, want ErrUnsupported", err)
	}
	if called {
		t.Fatal("key lookup ran for an algorithm the package cannot verify")
	}
}
