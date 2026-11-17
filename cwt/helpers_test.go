package cwt_test

// Helpers shared by the external tests in this package: CBOR and hex encoding, the RFC 8392 Appendix A
// values, and token builders for rule tests.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

func encode(t testing.TB, v any) []byte {
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

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func date(v int64) *cwt.NumericDate { return cwt.NewNumericDate(v) }

// Seeds from RFC 8392 Appendix A (also used, verbatim, by the protected tests in conformance/).
const (
	seedClaimsA1 = "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71"
	seedSignedA3 = "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30"
	seedMacedA4  = "d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200"
	keyA22       = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"
	keyA23Point  = "04143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"
)

func rfcKeys(t *testing.T) cwt.KeyFunc {
	t.Helper()
	hmacKey, err := hex.DecodeString(keyA22)
	if err != nil {
		t.Fatal(err)
	}
	point, err := hex.DecodeString(keyA23Point)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		t.Fatal(err)
	}
	return func(kid []byte, alg cwt.Algorithm) (any, error) {
		switch string(kid) {
		case "Symmetric256":
			return hmacKey, nil
		case "AsymmetricECDSA256":
			return pub, nil
		}
		return nil, errors.New("no such key")
	}
}

// insideA1Window is a moment inside RFC 8392 A.1's validity window (nbf 1443944944, exp 1444064944).
func insideA1Window() time.Time { return time.Unix(1443944944+60, 0) }

var testKey = []byte("0123456789abcdef0123456789abcdef")

// mac0Token builds a COSE_Mac0 token for rule tests. Its MAC structure follows RFC 9052 Section 6.3; the
// structure itself is checked against an outside vector in mac0_internal_test.go, so a shared mistake would show there.
type mac0Token struct {
	protectedRaw []byte // the encoded protected header map
	unprotected  map[int64]any
	payload      any // []byte, or nil for a detached payload
	alg          int64
	tagLen       int    // bytes of MAC tag to keep
	coseTag      uint64 // 0 for untagged
	cwtTag       bool
	key          []byte
}

func defaultMac0(t testing.TB) mac0Token {
	return mac0Token{
		protectedRaw: encode(t, map[int64]any{1: 5}),
		unprotected:  map[int64]any{},
		payload:      encode(t, map[int64]any{1: "issuer", 2: "subject"}),
		alg:          5,
		tagLen:       32,
		coseTag:      17,
		key:          testKey,
	}
}

func (m mac0Token) build(t testing.TB) []byte {
	t.Helper()
	var payloadBytes []byte
	if b, ok := m.payload.([]byte); ok {
		payloadBytes = b
	}
	toMac := encode(t, []any{"MAC0", m.protectedRaw, []byte{}, payloadBytes})
	h := hmac.New(sha256.New, m.key)
	h.Write(toMac)
	tag := h.Sum(nil)[:m.tagLen]
	var body any = []any{m.protectedRaw, m.unprotected, m.payload, tag}
	if m.coseTag != 0 {
		body = cbor.Tag{Number: m.coseTag, Content: body}
	}
	if m.cwtTag {
		body = cbor.Tag{Number: 61, Content: body}
	}
	return encode(t, body)
}

// es256Token signs claims as a tagged COSE_Sign1 with ES256 for rule tests. The signature structure is checked
// against an outside vector in sign1_internal_test.go.
func es256Token(t testing.TB, priv *ecdsa.PrivateKey, protected map[int64]any, sigLen int) []byte {
	t.Helper()
	protectedRaw := encode(t, protected)
	payload := encode(t, map[int64]any{1: "issuer"})
	digest := sha256.Sum256(encode(t, []any{"Signature1", protectedRaw, []byte{}, payload}))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return encode(t, cbor.Tag{Number: 18, Content: []any{protectedRaw, map[int64]any{}, payload, sig[:sigLen]}})
}

func seed(f *testing.F, hexes ...string) {
	for _, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
}

// checkClassified fails the fuzz run if err is not nil and wraps none of the documented kinds.
func checkClassified(t *testing.T, err error, kinds ...error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, k := range kinds {
		if errors.Is(err, k) {
			return
		}
	}
	t.Fatalf("unclassified error: %v", err)
}
