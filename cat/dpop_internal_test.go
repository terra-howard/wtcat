package cat

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// Outside vectors, copied from the RFCs' text by script.
const (
	// RFC 7638 Section 3.1: the example RSA key's modulus, and its JWK SHA-256 thumbprint.
	rfc7638N          = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	rfc7638Thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	// RFC 9449 Figure 5: an ES256 DPoP proof, its key in its header.
	rfc9449Figure5 = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"
)

var b64 = base64.RawURLEncoding

func TestThumbprintRFC7638(t *testing.T) {
	jwk := map[string]json.RawMessage{
		"kty": json.RawMessage(`"RSA"`), "n": json.RawMessage(`"` + rfc7638N + `"`), "e": json.RawMessage(`"AQAB"`),
		"alg": json.RawMessage(`"RS256"`), "kid": json.RawMessage(`"2011-04-29"`),
	}
	got, err := thumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if b64.EncodeToString(got) != rfc7638Thumbprint {
		t.Fatalf("thumbprint = %s, want %s", b64.EncodeToString(got), rfc7638Thumbprint)
	}
}

func TestParseProofRFC9449Figure5(t *testing.T) {
	p, err := parseProof(rfc9449Figure5)
	if err != nil {
		t.Fatalf("parseProof: %v", err)
	}
	if p.htm != "POST" || p.htu != "https://server.example.com/token" || p.iat != 1562262616 || p.jti != "-BwC3ESc6acc2lTc" || p.hasAth {
		t.Fatalf("proof = %+v", p)
	}
}

// proofParts builds a DPoP proof from a header and a payload, signed by key with alg.
func proofParts(t *testing.T, header, payload map[string]any, key crypto.Signer, alg string) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(pl)
	digest := sha256.Sum256([]byte(input))
	var sig []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case *rsa.PrivateKey:
		if sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			t.Fatal(err)
		}
	}
	_ = alg
	return input + "." + b64.EncodeToString(sig)
}

func ecJWK(k *ecdsa.PublicKey) map[string]any {
	x, y := make([]byte, 32), make([]byte, 32)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	return map[string]any{"kty": "EC", "crv": "P-256", "x": b64.EncodeToString(x), "y": b64.EncodeToString(y)}
}

func rsaJWK(k *rsa.PublicKey) map[string]any {
	return map[string]any{"kty": "RSA", "n": b64.EncodeToString(k.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(k.E)).Bytes())}
}

func basePayload() map[string]any {
	return map[string]any{"jti": "id-1", "htm": "GET", "htu": "https://cdn.example/a", "iat": 1700000000}
}

func TestParseProofAcceptsES256AndPS256(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"ES256": proofParts(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": ecJWK(&ec.PublicKey)}, basePayload(), ec, "ES256"),
		"PS256": proofParts(t, map[string]any{"typ": "dpop+jwt", "alg": "PS256", "jwk": rsaJWK(&rk.PublicKey)}, basePayload(), rk, "PS256"),
	} {
		p, err := parseProof(text)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(p.jkt) != 32 || p.htm != "GET" || p.iat != 1700000000 {
			t.Errorf("%s: proof = %+v", name, p)
		}
	}
}

func TestParseProofRefuses(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	header := func(mod func(map[string]any)) map[string]any {
		h := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": ecJWK(&ec.PublicKey)}
		mod(h)
		return h
	}
	payload := func(mod func(map[string]any)) map[string]any {
		p := basePayload()
		mod(p)
		return p
	}
	same := func(map[string]any) {}
	good := proofParts(t, header(same), payload(same), ec, "ES256")
	parts := strings.Split(good, ".")
	cases := map[string]string{
		"two parts":                          parts[0] + "." + parts[1],
		"padding":                            good + "=",
		"a changed signature":                parts[0] + "." + parts[1] + "." + b64.EncodeToString(make([]byte, 64)),
		"a changed payload":                  parts[0] + "." + b64.EncodeToString([]byte(`{"jti":"x","htm":"POST","htu":"https://cdn.example/a","iat":1700000000}`)) + "." + parts[2],
		"another typ":                        proofParts(t, header(func(h map[string]any) { h["typ"] = "jwt" }), payload(same), ec, "ES256"),
		"typ in another case of member name": proofParts(t, header(func(h map[string]any) { delete(h, "typ"); h["TYP"] = "dpop+jwt" }), payload(same), ec, "ES256"),
		"alg none":                           proofParts(t, header(func(h map[string]any) { h["alg"] = "none" }), payload(same), ec, "ES256"),
		"alg HS256":                          proofParts(t, header(func(h map[string]any) { h["alg"] = "HS256" }), payload(same), ec, "ES256"),
		"alg PS256 with an EC key":           proofParts(t, header(func(h map[string]any) { h["alg"] = "PS256" }), payload(same), ec, "ES256"),
		"a private key in jwk":               proofParts(t, header(func(h map[string]any) { h["jwk"].(map[string]any)["d"] = "AAAA" }), payload(same), ec, "ES256"),
		"curve P-384":                        proofParts(t, header(func(h map[string]any) { h["jwk"].(map[string]any)["crv"] = "P-384" }), payload(same), ec, "ES256"),
		"a short x":                          proofParts(t, header(func(h map[string]any) { h["jwk"].(map[string]any)["x"] = "AAAA" }), payload(same), ec, "ES256"),
		"an RSA key below 2048 bits":         proofParts(t, map[string]any{"typ": "dpop+jwt", "alg": "PS256", "jwk": rsaJWK(&small.PublicKey)}, payload(same), small, "PS256"),
		"a crit header":                      proofParts(t, header(func(h map[string]any) { h["crit"] = []string{"x"} }), payload(same), ec, "ES256"),
		"no jti":                             proofParts(t, header(same), payload(func(p map[string]any) { delete(p, "jti") }), ec, "ES256"),
		"an empty jti":                       proofParts(t, header(same), payload(func(p map[string]any) { p["jti"] = "" }), ec, "ES256"),
		"no htm":                             proofParts(t, header(same), payload(func(p map[string]any) { delete(p, "htm") }), ec, "ES256"),
		"no htu":                             proofParts(t, header(same), payload(func(p map[string]any) { delete(p, "htu") }), ec, "ES256"),
		"no iat":                             proofParts(t, header(same), payload(func(p map[string]any) { delete(p, "iat") }), ec, "ES256"),
		"iat a string":                       proofParts(t, header(same), payload(func(p map[string]any) { p["iat"] = "1700000000" }), ec, "ES256"),
		"ath not a string":                   proofParts(t, header(same), payload(func(p map[string]any) { p["ath"] = 1 }), ec, "ES256"),
		"a header that is not an object":     b64.EncodeToString([]byte(`[1]`)) + "." + parts[1] + "." + parts[2],
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseProof(text); err == nil {
				t.Fatal("parseProof accepted it")
			}
		})
	}
}
