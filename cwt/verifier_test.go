package cwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

func TestVerifierAcceptsRFCTokens(t *testing.T) {
	v := &cwt.Verifier{
		Algorithms: []cwt.Algorithm{cwt.HMAC256x64, cwt.ES256},
		Key:        rfcKeys(t),
		Now:        insideA1Window,
	}
	for name, token := range map[string]string{"A.4 MACed": seedMacedA4, "A.3 signed": seedSignedA3} {
		t.Run(name, func(t *testing.T) {
			c, err := v.Verify(mustHexBytes(t, token))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if c.Subject != "erikw" {
				t.Fatalf("sub = %q", c.Subject)
			}
		})
	}
}

func TestVerifierChecksTheAllowListBeforeKeyLookup(t *testing.T) {
	called := false
	v := &cwt.Verifier{
		Algorithms: []cwt.Algorithm{cwt.ES256},
		Key:        func([]byte, cwt.Algorithm) (any, error) { called = true; return nil, nil },
		Now:        insideA1Window,
	}
	if _, err := v.Verify(mustHexBytes(t, seedMacedA4)); !errors.Is(err, cwt.ErrUnsupported) {
		t.Fatalf("got %v, want ErrUnsupported", err)
	}
	if called {
		t.Fatal("the key function was called for an algorithm outside the allow-list")
	}
}

func TestVerifierWrapsKeyErrors(t *testing.T) {
	lookup := errors.New("key store unavailable")
	v := &cwt.Verifier{
		Algorithms: []cwt.Algorithm{cwt.HMAC256x64},
		Key:        func([]byte, cwt.Algorithm) (any, error) { return nil, lookup },
		Now:        insideA1Window,
	}
	_, err := v.Verify(mustHexBytes(t, seedMacedA4))
	if !errors.Is(err, cwt.ErrVerification) || !errors.Is(err, lookup) {
		t.Fatalf("got %v, want ErrVerification wrapping the key error", err)
	}
}

func TestVerifierRejectsAKeyOfTheWrongType(t *testing.T) {
	keys := rfcKeys(t)
	v := &cwt.Verifier{
		Algorithms: []cwt.Algorithm{cwt.HMAC256x64},
		// Hands back the signature key for an HMAC token: the classic confusion the design must refuse.
		Key: func([]byte, cwt.Algorithm) (any, error) { return keys([]byte("AsymmetricECDSA256"), cwt.ES256) },
		Now: insideA1Window,
	}
	if _, err := v.Verify(mustHexBytes(t, seedMacedA4)); !errors.Is(err, cwt.ErrVerification) {
		t.Fatalf("got %v, want ErrVerification", err)
	}
}

func TestVerifierChecksTime(t *testing.T) {
	v := &cwt.Verifier{
		Algorithms: []cwt.Algorithm{cwt.HMAC256x64},
		Key:        rfcKeys(t),
		Now:        func() time.Time { return time.Unix(1444064944, 0) },
	}
	if _, err := v.Verify(mustHexBytes(t, seedMacedA4)); !errors.Is(err, cwt.ErrExpired) {
		t.Fatalf("at exp: got %v, want ErrExpired", err)
	}
	v.Leeway = time.Minute
	if _, err := v.Verify(mustHexBytes(t, seedMacedA4)); err != nil {
		t.Fatalf("inside leeway: %v", err)
	}
}

func TestVerifierRequireExpiry(t *testing.T) {
	m := defaultMac0(t) // HMAC 256/256 over claims with no exp
	v := &cwt.Verifier{
		Algorithms:    []cwt.Algorithm{cwt.HMAC256x256},
		Key:           func([]byte, cwt.Algorithm) (any, error) { return testKey, nil },
		RequireExpiry: true,
	}
	if _, err := v.Verify(m.build(t)); !errors.Is(err, cwt.ErrMissingExpiry) {
		t.Fatalf("got %v, want ErrMissingExpiry", err)
	}
	v.RequireExpiry = false
	if _, err := v.Verify(m.build(t)); err != nil {
		t.Fatalf("without RequireExpiry: %v", err)
	}
}

func TestVerifierHandlesUntaggedTokensByAlgorithm(t *testing.T) {
	m := defaultMac0(t)
	m.coseTag = 0
	v := &cwt.Verifier{
		Algorithms: []cwt.Algorithm{cwt.HMAC256x256},
		Key:        func([]byte, cwt.Algorithm) (any, error) { return testKey, nil },
	}
	if _, err := v.Verify(m.build(t)); err != nil {
		t.Fatalf("untagged HMAC token: %v", err)
	}
}

func TestVerifierRejectsATagThatDisagreesWithTheAlgorithm(t *testing.T) {
	m := defaultMac0(t)
	m.coseTag = 18 // COSE_Sign1 tag on an HMAC token
	v := &cwt.Verifier{
		Algorithms: []cwt.Algorithm{cwt.HMAC256x256},
		Key:        func([]byte, cwt.Algorithm) (any, error) { return testKey, nil },
	}
	if _, err := v.Verify(m.build(t)); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestVerifierRejectsTheCWTTagAlone(t *testing.T) {
	token := encode(t, cbor.Tag{Number: 61, Content: []any{}})
	v := &cwt.Verifier{Algorithms: []cwt.Algorithm{cwt.ES256}, Key: rfcKeys(t)}
	if _, err := v.Verify(token); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestVerifierConfigurationErrors(t *testing.T) {
	token := mustHexBytes(t, seedMacedA4)
	for name, v := range map[string]*cwt.Verifier{
		"no algorithms":   {Key: rfcKeys(t)},
		"no key function": {Algorithms: []cwt.Algorithm{cwt.HMAC256x64}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(token)
			if err == nil || errors.Is(err, cwt.ErrVerification) || errors.Is(err, cwt.ErrMalformed) || errors.Is(err, cwt.ErrUnsupported) {
				t.Fatalf("got %v, want a plain configuration error", err)
			}
		})
	}
}

// Added after Gremlins (task 11). Covers the Verifier's rejection of a tag that is neither COSE_Mac0 nor COSE_Sign1.
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

// Added after Gremlins (task 11). Covers the Verifier's refusal of an allowed algorithm it cannot verify.
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
