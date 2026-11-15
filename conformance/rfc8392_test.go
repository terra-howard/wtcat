package conformance

// Protected tests from RFC 8392, Appendix A (https://www.rfc-editor.org/rfc/rfc8392).
//
// Every hex value below was copied from the RFC's text by script, not typed by this project. Errata checked on
// 2026-11-14 (https://www.rfc-editor.org/errata/rfc8392): erratum 7982 and a report of 2025-11-25 concern the
// COSE_Key encoding in A.2.2 (its kid label and its alg byte). These tests use only that key's raw k value, which
// neither report disputes, and take the MAC algorithm from the token's own protected header. An editorial erratum
// on A.3 concerns line wrapping only; its reporter confirms the bytes are correct.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/terra-howard/wtcat/cwt"
)

const (
	// Figure 2: the example CWT Claims Set.
	claimsSetA1 = "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71"
	// Figure 10: the signed CWT (COSE_Sign1, ES256).
	signedA3 = "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30"
	// Section A.4: the MACed CWT (CWT tag, COSE_Mac0, HMAC 256/64).
	macedA4 = "d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200"
	// Figure 6: the k parameter of the 256-bit symmetric key.
	keyA22 = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"
	// Figure 8: the x and y parameters of the P-256 key.
	keyA23X = "143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f"
	keyA23Y = "60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// tamper replaces the only occurrence of old with new in the hex form of a token.
func tamper(token, old, new string) []byte {
	if strings.Count(token, old) != 1 {
		panic("tamper: expected exactly one occurrence of " + old)
	}
	return mustHex(strings.Replace(token, old, new, 1))
}

// flipLastByte changes the final byte of a token, which is the last byte of its MAC tag or signature.
func flipLastByte(token string) []byte {
	b := mustHex(token)
	b[len(b)-1] ^= 0x01
	return b
}

func publicKeyA23(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	point := append([]byte{0x04}, append(mustHex(keyA23X), mustHex(keyA23Y)...)...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		t.Fatalf("the RFC's public key does not parse: %v", err)
	}
	return pub
}

// checkClaimsA1 compares decoded claims with Figure 3, the diagnostic notation of the example claims set.
func checkClaimsA1(t *testing.T, c *cwt.Claims) {
	t.Helper()
	if c == nil {
		t.Fatal("got nil claims")
	}
	if c.Issuer != "coap://as.example.com" {
		t.Errorf("iss = %q, want %q", c.Issuer, "coap://as.example.com")
	}
	if c.Subject != "erikw" {
		t.Errorf("sub = %q, want %q", c.Subject, "erikw")
	}
	if len(c.Audience) != 1 || c.Audience[0] != "coap://light.example.com" {
		t.Errorf("aud = %q, want [%q]", c.Audience, "coap://light.example.com")
	}
	checkDate(t, "exp", c.Expiry, 1444064944)
	checkDate(t, "nbf", c.NotBefore, 1443944944)
	checkDate(t, "iat", c.IssuedAt, 1443944944)
	if !bytes.Equal(c.CWTID, []byte{0x0b, 0x71}) {
		t.Errorf("cti = %x, want 0b71", c.CWTID)
	}
	if len(c.Other) != 0 {
		t.Errorf("got %d unexpected claims", len(c.Other))
	}
}

func checkDate(t *testing.T, name string, got *cwt.NumericDate, want int64) {
	t.Helper()
	if got == nil {
		t.Errorf("%s is absent, want %d", name, want)
	} else if got.Unix() != want || got.Fraction() != 0 {
		t.Errorf("%s = %d and %v, want %d exactly", name, got.Unix(), got.Fraction(), want)
	}
}

func TestRFC8392A1ClaimsSet(t *testing.T) {
	c, err := cwt.DecodeClaims(mustHex(claimsSetA1))
	if err != nil {
		t.Fatalf("DecodeClaims: %v", err)
	}
	checkClaimsA1(t, c)
}

func TestRFC8392A3SignedCWT(t *testing.T) {
	c, err := cwt.VerifySign1(mustHex(signedA3), publicKeyA23(t))
	if err != nil {
		t.Fatalf("VerifySign1: %v", err)
	}
	checkClaimsA1(t, c)
}

func TestRFC8392A3RejectsTampering(t *testing.T) {
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		token []byte
		key   *ecdsa.PublicKey
	}{
		{"payload changed", tamper(signedA3, "6572696b77", "6572696b78"), publicKeyA23(t)}, // sub "erikw" becomes "erikx"
		{"signature changed", flipLastByte(signedA3), publicKeyA23(t)},
		{"wrong key", mustHex(signedA3), &otherKey.PublicKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cwt.VerifySign1(tc.token, tc.key); !errors.Is(err, cwt.ErrVerification) {
				t.Fatalf("got %v, want an error wrapping cwt.ErrVerification", err)
			}
		})
	}
}

func TestRFC8392A4MACedCWT(t *testing.T) {
	c, err := cwt.VerifyMac0(mustHex(macedA4), mustHex(keyA22))
	if err != nil {
		t.Fatalf("VerifyMac0: %v", err)
	}
	checkClaimsA1(t, c)
}

func TestRFC8392A4RejectsTampering(t *testing.T) {
	wrongKey := mustHex(keyA22)
	wrongKey[0] ^= 0x01
	cases := []struct {
		name  string
		token []byte
		key   []byte
	}{
		{"payload changed", tamper(macedA4, "6572696b77", "6572696b78"), mustHex(keyA22)}, // sub "erikw" becomes "erikx"
		{"tag changed", flipLastByte(macedA4), mustHex(keyA22)},
		{"tag truncated", tamper(macedA4, "48093101ef6d789200", "47093101ef6d7892"), mustHex(keyA22)}, // 8-byte tag cut to 7
		{"wrong key", mustHex(macedA4), wrongKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cwt.VerifyMac0(tc.token, tc.key); !errors.Is(err, cwt.ErrVerification) {
				t.Fatalf("got %v, want an error wrapping cwt.ErrVerification", err)
			}
		})
	}
}
