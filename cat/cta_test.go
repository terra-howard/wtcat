//go:build cta

package cat_test

// Tests against CTA-5007-B's own examples (Annex A.3, with the keys of Annex B.2 and B.3). The examples are not in
// this repository (decision 0014). Produce them from your own copy of the document:
//
//	pdftotext "CTA-5007-B.pdf" cta.txt
//	go run ./cmd/ctaexamples cta.txt
//	go test -tags cta ./cat
//
// The ES256 examples are left out: they do not verify with the document's published key, which is a secp256k1
// key rather than P-256 (decision 0015).

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
	"github.com/terra-howard/wtcat/internal/ctaexamples"
)

func loadCTAExamples(t *testing.T) ctaexamples.Examples {
	t.Helper()
	path := filepath.Join("..", "testdata", "cta-local", "examples.json")
	data, err := os.ReadFile(path)
	if err != nil {
		// A test someone asked for by setting the cta tag fails rather than skips (decision 0014).
		t.Fatalf("%v\n\nThese tests need the specification's examples. From the repository root:\n"+
			"\tpdftotext \"CTA-5007-B.pdf\" cta.txt\n\tgo run ./cmd/ctaexamples cta.txt", err)
	}
	var ex ctaexamples.Examples
	if err := json.Unmarshal(data, &ex); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return ex
}

func ctaKeys(t *testing.T, ex ctaexamples.Examples) map[string]cwt.Key {
	t.Helper()
	secret, err := base64.StdEncoding.DecodeString(ex.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(ex.PS256PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("the PS256 public key is a %T", pub)
	}
	return map[string]cwt.Key{
		"HMAC 256/256": {Algorithm: cwt.HMAC256x256, Material: secret},
		"PS256":        {Algorithm: cwt.PS256, Material: rsaKey},
	}
}

func validatorWith(key cwt.Key) *cat.Validator {
	return &cat.Validator{
		Keys: func([]byte) (cat.Key, error) { return cat.Key{Key: key}, nil },
		Now:  func() time.Time { return time.Unix(1699999999, 0) }, // before the examples' exp
	}
}

// catuPrefix reads the path prefix the example's own catu claim requires, from the verified token, so that no
// value from the document is written into this repository.
func catuPrefix(t *testing.T, token string, key cwt.Key) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := cwt.VerifyMessage(raw, func([]byte) (cwt.Key, error) { return key, nil })
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	var claims struct {
		Catu map[int64]map[int64]string `cbor:"312,keyasint"`
	}
	if err := cbor.Unmarshal(msg.Payload, &claims); err != nil {
		t.Fatalf("reading catu: %v", err)
	}
	prefix, ok := claims.Catu[3][1]
	if !ok {
		t.Fatalf("the example's catu has no path prefix match: %v", claims.Catu)
	}
	return prefix
}

// The examples restrict the path by a prefix match in catu (decision 0017's phase 2). Each is accepted for a URI
// under that prefix before its exp, and refused outside it.
func TestCTAExamplesAreAcceptedOnlyUnderTheirPathPrefix(t *testing.T) {
	ex := loadCTAExamples(t)
	keys := ctaKeys(t, ex)
	for name, token := range map[string]string{"HMAC 256/256": ex.HMACToken, "PS256": ex.PS256Token} {
		t.Run(name, func(t *testing.T) {
			prefix := catuPrefix(t, token, keys[name])
			v := validatorWith(keys[name])
			inside := &cat.Request{Method: "GET", URI: "https://cdn.example" + prefix + "index.m3u8"}
			if _, err := v.ValidateRequest(token, inside); err != nil {
				t.Fatalf("under the prefix: %v", err)
			}
			outside := &cat.Request{Method: "GET", URI: "https://cdn.example/elsewhere/index.m3u8"}
			if _, err := v.ValidateRequest(token, outside); !errors.Is(err, cat.ErrURI) {
				t.Fatalf("outside the prefix: got %v, want cat.ErrURI", err)
			}
			if _, err := v.Validate(token); !errors.Is(err, cwt.ErrUnsupported) {
				t.Fatalf("without a request: got %v, want cwt.ErrUnsupported", err)
			}
		})
	}
}

func TestCTAExamplesVerifyOnlyWithTheirOwnKeys(t *testing.T) {
	ex := loadCTAExamples(t)
	keys := ctaKeys(t, ex)
	wrongSecret := append([]byte(nil), keys["HMAC 256/256"].Material.([]byte)...)
	wrongSecret[0] ^= 1
	for name, tc := range map[string]struct {
		token string
		key   cwt.Key
	}{
		"HMAC 256/256 with a changed key": {ex.HMACToken, cwt.Key{Algorithm: cwt.HMAC256x256, Material: wrongSecret}},
		"PS256 with the HMAC key":         {ex.PS256Token, keys["HMAC 256/256"]},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validatorWith(tc.key).Validate(tc.token)
			if err == nil || errors.Is(err, cwt.ErrUnsupported) {
				t.Fatalf("got %v, want the token refused before its claims are read", err)
			}
		})
	}
}
