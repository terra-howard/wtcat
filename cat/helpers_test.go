package cat_test

// Helpers shared by the external tests in this package: a deterministic CBOR encoder and token builders.

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

// detEnc encodes with the shortest floats, so test tokens are deterministically encoded (integers always are).
var detEnc = func() cbor.EncMode {
	em, err := cbor.EncOptions{ShortestFloat: cbor.ShortestFloat16}.EncMode()
	if err != nil {
		panic(err)
	}
	return em
}()

func enc(t testing.TB, v any) []byte {
	t.Helper()
	b, err := detEnc.Marshal(v)
	if err != nil {
		t.Fatalf("encoding test input: %v", err)
	}
	return b
}

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad test hex: %v", err)
	}
	return b
}

var (
	hmacSecret = []byte("0123456789abcdef0123456789abcdef")
	// testNow is the clock every Validator in these tests reads unless a test sets its own.
	testNow = time.Unix(1700000000, 0)
)

// mac0 describes a COSE_Mac0 CAT with HMAC 256/256 for tests.
type mac0 struct {
	protected []byte // the encoded protected header; nil means {1: 5}
	kid       []byte // put in the unprotected header when not nil
	payload   []byte // the encoded claim set
	// unprotectedExtra adds parameters to the unprotected header.
	unprotectedExtra map[int64]any
}

func (m mac0) bytes(t testing.TB) []byte {
	t.Helper()
	protected := m.protected
	if protected == nil {
		protected = enc(t, map[int64]any{1: 5})
	}
	unprotected := map[int64]any{}
	if m.kid != nil {
		unprotected[4] = m.kid
	}
	for k, v := range m.unprotectedExtra {
		unprotected[k] = v
	}
	h := hmac.New(sha256.New, hmacSecret)
	h.Write(enc(t, []any{"MAC0", protected, []byte{}, m.payload}))
	return enc(t, cbor.Tag{Number: 17, Content: []any{protected, unprotected, m.payload, h.Sum(nil)}})
}

func (m mac0) text(t testing.TB) string { return base64.RawURLEncoding.EncodeToString(m.bytes(t)) }

// claimsToken is an HMAC 256/256 CAT with kid "k1" carrying the given claims.
func claimsToken(t testing.TB, claims map[any]any) string {
	t.Helper()
	return mac0{kid: []byte("k1"), payload: enc(t, claims)}.text(t)
}

// es256Text signs a claim set as a tagged COSE_Sign1 with ES256 and no alg header.
func es256Text(t testing.TB, priv *ecdsa.PrivateKey, claims map[any]any) string {
	t.Helper()
	protected := []byte{}
	payload := enc(t, claims)
	digest := sha256.Sum256(enc(t, []any{"Signature1", protected, []byte{}, payload}))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(enc(t, cbor.Tag{Number: 18, Content: []any{protected, map[int64]any{}, payload, sig}}))
}

// keys returns a KeyFunc with the HMAC key "k1" for issuer "issuer", and records each kid asked for.
func keys(asked *[][]byte) cat.KeyFunc {
	return func(kid []byte) (cat.Key, error) {
		if asked != nil {
			*asked = append(*asked, kid)
		}
		if kid != nil && string(kid) != "k1" {
			return cat.Key{}, errors.New("no such key")
		}
		return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: hmacSecret}, Issuer: "issuer"}, nil
	}
}

func validator() *cat.Validator {
	return &cat.Validator{Keys: keys(nil), Audiences: []string{"cdn.example"}, Now: func() time.Time { return testNow }}
}

func at(v *cat.Validator, now time.Time) *cat.Validator {
	v.Now = func() time.Time { return now }
	return v
}

func wantKind(t *testing.T, err error, kind error) {
	t.Helper()
	if !errors.Is(err, kind) {
		t.Fatalf("got %v, want an error wrapping %v", err, kind)
	}
}
