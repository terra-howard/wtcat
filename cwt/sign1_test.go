package cwt_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

func TestVerifySign1ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cwt.VerifySign1(es256Token(t, priv, map[int64]any{1: -7}, 64), &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifySign1: %v", err)
	}
	if c.Issuer != "issuer" {
		t.Fatalf("iss = %q", c.Issuer)
	}
}

func TestVerifySign1PS256(t *testing.T) {
	priv, err := testRSAKey(t, 2048)
	if err != nil {
		t.Fatal(err)
	}
	protectedRaw := encode(t, map[int64]any{1: -37})
	payload := encode(t, map[int64]any{1: "issuer"})
	digest := sha256.Sum256(encode(t, []any{"Signature1", protectedRaw, []byte{}, payload}))
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatal(err)
	}
	token := encode(t, cbor.Tag{Number: 18, Content: []any{protectedRaw, map[int64]any{}, payload, sig}})
	c, err := cwt.VerifySign1(token, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifySign1: %v", err)
	}
	if c.Issuer != "issuer" {
		t.Fatalf("iss = %q", c.Issuer)
	}
}

// TestVerifySign1RejectsNonCanonicalES256 drops the leading zero byte of s from a valid signature. The value is
// unchanged, so only the 64-byte length rule can reject it. (Hand mutation testing showed a looser length check
// survived the earlier short-signature test, which dropped an arbitrary byte.)
func TestVerifySign1RejectsNonCanonicalES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	protectedRaw := encode(t, map[int64]any{1: -7})
	payload := encode(t, map[int64]any{1: "issuer"})
	digest := sha256.Sum256(encode(t, []any{"Signature1", protectedRaw, []byte{}, payload}))
	var sig []byte
	for i := 0; i < 10000 && sig == nil; i++ { // about 1 in 256 signatures has s below 2^248
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		full := make([]byte, 64)
		r.FillBytes(full[:32])
		s.FillBytes(full[32:])
		if full[32] == 0 {
			sig = append(full[:32:32], full[33:]...) // 63 bytes, same r and s values
		}
	}
	if sig == nil {
		t.Fatal("no signature with a leading zero in s after 10000 tries")
	}
	token := encode(t, cbor.Tag{Number: 18, Content: []any{protectedRaw, map[int64]any{}, payload, sig}})
	if _, err := cwt.VerifySign1(token, &priv.PublicKey); !errors.Is(err, cwt.ErrVerification) {
		t.Fatalf("got %v, want ErrVerification for a 63-byte encoding", err)
	}
}

func TestVerifySign1Rejects(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := testRSAKey(t, 2048)
	if err != nil {
		t.Fatal(err)
	}
	good := es256Token(t, priv, map[int64]any{1: -7}, 64)
	cases := []struct {
		name  string
		token []byte
		key   any
		want  error
	}{
		{"RSA key for ES256", good, &rsaKey.PublicKey, cwt.ErrVerification},
		{"P-384 key for ES256", good, &p384.PublicKey, cwt.ErrVerification},
		{"HMAC key for ES256", good, []byte("secret"), cwt.ErrVerification},
		{"nil key", good, nil, cwt.ErrVerification},
		{"short signature", es256Token(t, priv, map[int64]any{1: -7}, 63), &priv.PublicKey, cwt.ErrVerification},
		{"HMAC algorithm in a COSE_Sign1", es256Token(t, priv, map[int64]any{1: 5}, 64), &priv.PublicKey, cwt.ErrUnsupported},
		{"PS256 label on an ECDSA signature", es256Token(t, priv, map[int64]any{1: -37}, 64), &rsaKey.PublicKey, cwt.ErrVerification},
		{"ECDSA key for PS256", es256Token(t, priv, map[int64]any{1: -37}, 64), &priv.PublicKey, cwt.ErrVerification},
		{"COSE_Mac0 tag", encode(t, cbor.Tag{Number: 17, Content: []any{encode(t, map[int64]any{1: -7}), map[int64]any{}, []byte{0xa0}, make([]byte, 64)}}), &priv.PublicKey, cwt.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cwt.VerifySign1(tc.token, tc.key); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want an error wrapping %v", err, tc.want)
			}
		})
	}
}

// Added after Gremlins (task 11). Kills mutants that would let a typed nil key through to a nil dereference.
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

func FuzzVerifySign1(f *testing.F) {
	seed(f, seedSignedA3, seedMacedA4, seedClaimsA1)
	point, err := hex.DecodeString(keyA23Point)
	if err != nil {
		f.Fatal(err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := cwt.VerifySign1(data, pub)
		checkClassified(t, err, cwt.ErrVerification, cwt.ErrMalformed, cwt.ErrUnsupported)
		if err == nil && c == nil {
			t.Fatal("nil claims without an error")
		}
	})
}
