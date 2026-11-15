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
	"strings"
	"testing"
	"time"

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

// Phase 1 of decision 0015: the examples are well formed, deterministically encoded and authentic, and they carry
// catu, which phase 1 does not enforce yet, so Validate refuses them as unsupported. Reaching that refusal means
// every earlier step passed. In phase 2 these tests change to accept the examples for a matching request.
func TestCTAExamplesReachTheClaimsAndAreRefusedForCatu(t *testing.T) {
	ex := loadCTAExamples(t)
	keys := ctaKeys(t, ex)
	for name, token := range map[string]string{"HMAC 256/256": ex.HMACToken, "PS256": ex.PS256Token} {
		t.Run(name, func(t *testing.T) {
			_, err := validatorWith(keys[name]).Validate(token)
			if !errors.Is(err, cwt.ErrUnsupported) || !strings.Contains(err.Error(), "catu") {
				t.Fatalf("got %v, want the unsupported-claim refusal for catu", err)
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
