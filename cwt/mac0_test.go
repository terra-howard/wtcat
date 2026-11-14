package cwt_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

// mac0Token builds a COSE_Mac0 token for rule tests. Its MAC structure follows RFC 9052 Section 6.3; the
// structure itself is checked against an outside vector in cose_wg_test.go, so a shared mistake would show there.
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

func defaultMac0(t *testing.T) mac0Token {
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

func (m mac0Token) build(t *testing.T) []byte {
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

func TestVerifyMac0AcceptsHMAC256(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*mac0Token)
	}{
		{"tagged", func(m *mac0Token) {}},
		{"untagged", func(m *mac0Token) { m.coseTag = 0 }},
		{"with CWT tag", func(m *mac0Token) { m.cwtTag = true }},
		{"kid unprotected", func(m *mac0Token) { m.unprotected = map[int64]any{4: []byte("key-1")} }},
		{"kid protected", func(m *mac0Token) { m.protectedRaw = encode(t, map[int64]any{1: 5, 4: []byte("key-1")}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := defaultMac0(t)
			tc.modify(&m)
			c, err := cwt.VerifyMac0(m.build(t), testKey)
			if err != nil {
				t.Fatalf("VerifyMac0: %v", err)
			}
			if c.Issuer != "issuer" || c.Subject != "subject" {
				t.Fatalf("claims = %+v", c)
			}
		})
	}
}

func TestVerifyMac0Rejects(t *testing.T) {
	cases := []struct {
		name   string
		modify func(*mac0Token)
		key    []byte
		want   error
	}{
		{"wrong key", func(m *mac0Token) {}, []byte("another key of thirty-two bytes!"), cwt.ErrVerification},
		{"empty key", func(m *mac0Token) {}, []byte{}, cwt.ErrVerification},
		{"HMAC 256/256 tag cut to 8 bytes", func(m *mac0Token) { m.tagLen = 8 }, testKey, cwt.ErrVerification},
		{"COSE_Sign1 tag", func(m *mac0Token) { m.coseTag = 18 }, testKey, cwt.ErrMalformed},
		{"CWT tag without a COSE tag", func(m *mac0Token) { m.cwtTag, m.coseTag = true, 0 }, testKey, cwt.ErrMalformed},
		{"alg missing", func(m *mac0Token) { m.protectedRaw = []byte{} }, testKey, cwt.ErrMalformed},
		{"alg only unprotected", func(m *mac0Token) { m.protectedRaw = []byte{}; m.unprotected = map[int64]any{1: 5} }, testKey, cwt.ErrMalformed},
		{"alg a signature algorithm", func(m *mac0Token) { m.protectedRaw = encode(t, map[int64]any{1: -7}) }, testKey, cwt.ErrUnsupported},
		{"crit header", func(m *mac0Token) { m.protectedRaw = encode(t, map[int64]any{1: 5, 2: []int64{4}}) }, testKey, cwt.ErrUnsupported},
		{"content type header", func(m *mac0Token) { m.unprotected = map[int64]any{3: 61} }, testKey, cwt.ErrUnsupported},
		{"text header label", func(m *mac0Token) {
			m.unprotected = map[int64]any{}
			m.protectedRaw = encode(t, map[any]any{int64(1): 5, "x": 1})
		}, testKey, cwt.ErrUnsupported},
		{"kid in both headers", func(m *mac0Token) {
			m.protectedRaw = encode(t, map[int64]any{1: 5, 4: []byte("a")})
			m.unprotected = map[int64]any{4: []byte("a")}
		}, testKey, cwt.ErrMalformed},
		{"kid not a byte string", func(m *mac0Token) { m.unprotected = map[int64]any{4: "key-1"} }, testKey, cwt.ErrMalformed},
		{"duplicate protected label", func(m *mac0Token) { m.protectedRaw = []byte{0xa2, 0x01, 0x05, 0x01, 0x05} }, testKey, cwt.ErrMalformed},
		{"detached payload", func(m *mac0Token) { m.payload = nil }, testKey, cwt.ErrUnsupported},
		{"nested CWT", func(m *mac0Token) { m.payload = encode(t, cbor.Tag{Number: 17, Content: []any{}}) }, testKey, cwt.ErrUnsupported},
		{"payload not a claims map", func(m *mac0Token) { m.payload = encode(t, "hello") }, testKey, cwt.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := defaultMac0(t)
			tc.modify(&m)
			if _, err := cwt.VerifyMac0(m.build(t), tc.key); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want an error wrapping %v", err, tc.want)
			}
		})
	}
}

func TestVerifyMac0RejectsWrongShapes(t *testing.T) {
	cases := map[string][]byte{
		"not CBOR":          {0xff},
		"three elements":    encode(t, cbor.Tag{Number: 17, Content: []any{[]byte{}, map[int64]any{}, []byte{}}}),
		"protected a map":   encode(t, cbor.Tag{Number: 17, Content: []any{map[int64]any{1: 5}, map[int64]any{}, []byte{}, []byte{}}}),
		"tag a text string": encode(t, cbor.Tag{Number: 17, Content: []any{encode(t, map[int64]any{1: 5}), map[int64]any{}, []byte{}, "tag"}}),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := cwt.VerifyMac0(token, testKey); !errors.Is(err, cwt.ErrMalformed) {
				t.Fatalf("got %v, want an error wrapping cwt.ErrMalformed", err)
			}
		})
	}
}
