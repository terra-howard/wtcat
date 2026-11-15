package ctaexamples

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The tests build a synthetic document in this project's own words, laid out the way pdftotext lays out the real
// one: wrapped lines, page breaks with a page number and a running header inside a token, PEM armour that has lost
// a dash, and decoys. No text from CTA-5007-B appears here.

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type fixture struct {
	hmacToken, hmacKey, ps256Token, ps256Key string
	document                                 string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	payload := marshal(t, map[int64]any{4: 1700000000})

	macProtected := marshal(t, map[int64]any{1: 5})
	h := hmac.New(sha256.New, secret)
	h.Write(marshal(t, []any{"MAC0", macProtected, []byte{}, payload}))
	hmacToken := marshal(t, cbor.Tag{Number: 17, Content: []any{macProtected, map[int64]any{}, payload, h.Sum(nil)}})

	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	sigProtected := marshal(t, map[int64]any{1: -37})
	digest := sha256.Sum256(marshal(t, []any{"Signature1", sigProtected, []byte{}, payload}))
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatal(err)
	}
	ps256Token := marshal(t, cbor.Tag{Number: 18, Content: []any{sigProtected, map[int64]any{}, payload, sig}})
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	f := fixture{
		hmacToken:  base64.RawURLEncoding.EncodeToString(hmacToken),
		hmacKey:    base64.StdEncoding.EncodeToString(secret),
		ps256Token: base64.RawURLEncoding.EncodeToString(ps256Token),
		ps256Key:   base64.StdEncoding.EncodeToString(der),
	}
	pageBreak := "\n17\n\x0cCTA-5007-B\n"
	wrap := func(s string, width int) string {
		var lines []string
		for len(s) > width {
			lines = append(lines, s[:width])
			s = s[width:]
		}
		return strings.Join(append(lines, s), "\n")
	}
	half := len(f.hmacToken) / 2
	decoyKey := base64.StdEncoding.EncodeToString(make([]byte, 32)) // the right shape, the wrong key
	f.document = strings.Join([]string{
		"Some words about tokens.",
		"https://cdn.example/" + f.ps256Token[:40] + "\n" + f.ps256Token[40:300] + pageBreak + f.ps256Token[300:] + "/index.m3u8 more words",
		"A token printed on its own: " + f.hmacToken[:half] + pageBreak + f.hmacToken[half:] + "Then text resumes.",
		"And again: " + wrap(f.hmacToken, 64),
		"-----BEGIN PUBLIC KEY----" + wrap(f.ps256Key, 64) + " -----END PUBLIC KEY-----",
		"A decoy of the right shape: " + decoyKey,
		"The key: " + f.hmacKey[:7] + "\n" + f.hmacKey[7:] + " ends here.",
	}, "\n")
	return f
}

func TestExtractRecoversEveryExample(t *testing.T) {
	f := newFixture(t)
	got, err := Extract(f.document)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	for name, pair := range map[string][2]string{
		"HMAC token":  {got.HMACToken, f.hmacToken},
		"HMAC key":    {got.HMACKey, f.hmacKey},
		"PS256 token": {got.PS256Token, f.ps256Token},
		"PS256 key":   {got.PS256PublicKey, f.ps256Key},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}
}

func TestExtractFailsLoudly(t *testing.T) {
	f := newFixture(t)
	for name, doc := range map[string]string{
		"no HMAC token":             strings.ReplaceAll(f.document, "0YRDoQEF", "0YRDoQEG"),
		"no PS256 token":            strings.ReplaceAll(f.document, "0oREoQE4", "0oREoQE5"),
		"no RSA public key":         strings.ReplaceAll(f.document, "BEGIN PUBLIC KEY", "BEGIN OTHER THING"),
		"no HMAC key verifies":      strings.ReplaceAll(f.document, f.hmacKey[7:], strings.Repeat("A", len(f.hmacKey)-8)+"="),
		"two different HMAC tokens": f.document + "\n" + mutateLast(f.hmacToken),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Extract(doc); err == nil {
				t.Fatal("got nil error")
			}
		})
	}
}

// mutateLast changes a token's final character, so it still parses but carries a different MAC.
func mutateLast(token string) string {
	last := token[len(token)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'Q'
	}
	return token[:len(token)-1] + string(repl)
}
