// Package ctaexamples finds CTA-5007-B's HMAC 256/256 and PS256 examples in the text of a contributor's own copy
// of the document, so they can be used as test vectors without being published (decision 0014).
//
// It locates everything by structure, never by the document's prose: the page breaks pdftotext leaves inside
// long strings, the CBOR prefixes a COSE_Mac0 or COSE_Sign1 token with those algorithms must begin with, the end
// of the CBOR item itself, PEM armour, and the shape of a base64-encoded 256-bit key. Each key is then confirmed
// by verifying its token, so a wrong extraction fails instead of yielding a wrong vector. The ES256 examples are
// not extracted: they do not verify with the document's published key (decision 0015).
package ctaexamples

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

// Examples are the extracted vectors, each in the text form the document prints.
type Examples struct {
	HMACToken      string `json:"hmac_token"`       // base64url
	HMACKey        string `json:"hmac_key"`         // base64 of the 256-bit secret
	PS256Token     string `json:"ps256_token"`      // base64url
	PS256PublicKey string `json:"ps256_public_key"` // base64 of the DER SubjectPublicKeyInfo
}

// Base64url prefixes of a tagged COSE_Mac0 whose protected header is {1: 5} (HMAC 256/256), and of a tagged
// COSE_Sign1 whose protected header is {1: -37} (PS256).
const (
	prefixHMAC  = "0YRDoQEF"
	prefixPS256 = "0oREoQE4"
)

var (
	// pageBreak matches what pdftotext leaves at a page boundary: the page number, a form feed and the running
	// header, which is the document's designation.
	pageBreak = regexp.MustCompile(`\n[ivx\d]+\s*\n\s*\x0c\s*CTA-5007-B[^\n]*\n`)
	// keyShape matches a base64-encoded 32-byte value: 43 characters and one padding character.
	keyShape = regexp.MustCompile(`[A-Za-z0-9+/]{43}=`)
	// publicKeyPEM matches a PEM public key block, tolerating armour that has lost dashes.
	publicKeyPEM = regexp.MustCompile(`BEGIN PUBLIC KEY-*([A-Za-z0-9+/=\s]+?)-*END PUBLIC KEY`)
)

// Extract finds and confirms the examples in the text of the document, as pdftotext writes it without -layout.
func Extract(text string) (*Examples, error) {
	text = pageBreak.ReplaceAllString(text, "\n")
	flat := strings.Join(strings.Fields(text), "")

	hmacToken, err := findToken(flat, prefixHMAC)
	if err != nil {
		return nil, fmt.Errorf("HMAC 256/256 token: %w", err)
	}
	psToken, err := findToken(flat, prefixPS256)
	if err != nil {
		return nil, fmt.Errorf("PS256 token: %w", err)
	}

	var hmacKey string
	for _, candidate := range keyShape.FindAllString(flat, -1) {
		secret, err := base64.StdEncoding.DecodeString(candidate)
		if err != nil || len(secret) != 32 {
			continue
		}
		if verifies(hmacToken, cwt.Key{Algorithm: cwt.HMAC256x256, Material: secret}) {
			hmacKey = candidate
			break
		}
	}
	if hmacKey == "" {
		return nil, errors.New("no 256-bit key in the text verifies the HMAC 256/256 token")
	}

	var psKey string
	for _, m := range publicKeyPEM.FindAllStringSubmatch(text, -1) {
		body := strings.Join(strings.Fields(m[1]), "")
		der, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			continue
		}
		if rsaKey, ok := pub.(*rsa.PublicKey); ok && verifies(psToken, cwt.Key{Algorithm: cwt.PS256, Material: rsaKey}) {
			psKey = body
			break
		}
	}
	if psKey == "" {
		return nil, errors.New("no RSA public key in the text verifies the PS256 token")
	}

	return &Examples{
		HMACToken:      base64.RawURLEncoding.EncodeToString(hmacToken),
		HMACKey:        hmacKey,
		PS256Token:     base64.RawURLEncoding.EncodeToString(psToken),
		PS256PublicKey: psKey,
	}, nil
}

// findToken returns the token every occurrence of prefix begins, cut where its CBOR item ends. Every printed copy
// must agree.
func findToken(flat, prefix string) ([]byte, error) {
	var token []byte
	copies := 0
	for i := strings.Index(flat, prefix); i >= 0; i = nextIndex(flat, prefix, i) {
		run := flat[i:]
		if end := strings.IndexFunc(run, func(r rune) bool { return !isBase64URL(r) }); end >= 0 {
			run = run[:end]
		}
		if len(run)%4 == 1 { // a length no base64 string can have: the last character is not the token's
			run = run[:len(run)-1]
		}
		data, err := base64.RawURLEncoding.DecodeString(run)
		if err != nil {
			return nil, fmt.Errorf("copy %d: %v", copies+1, err)
		}
		var item cbor.RawMessage
		if _, err := cbor.UnmarshalFirst(data, &item); err != nil {
			return nil, fmt.Errorf("copy %d is not a complete CBOR item: %v", copies+1, err)
		}
		copies++
		if token == nil {
			token = item
		} else if string(token) != string(item) {
			return nil, fmt.Errorf("printed copies disagree (copy %d differs from copy 1)", copies)
		}
	}
	if token == nil {
		return nil, errors.New("not found")
	}
	return token, nil
}

func nextIndex(s, sub string, after int) int {
	j := strings.Index(s[after+1:], sub)
	if j < 0 {
		return -1
	}
	return after + 1 + j
}

func isBase64URL(r rune) bool {
	return 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '-' || r == '_'
}

func verifies(token []byte, key cwt.Key) bool {
	_, err := cwt.VerifyMessage(token, func([]byte) (cwt.Key, error) { return key, nil })
	return err == nil
}
