package cat_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

var b64url = base64.RawURLEncoding

// dpopKey is a client's DPoP key, with its public JWK and RFC 7638 thumbprint.
type dpopKey struct {
	priv *ecdsa.PrivateKey
	jwk  map[string]any
	jkt  []byte
}

func newDPoPKey(t *testing.T) dpopKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := make([]byte, 32), make([]byte, 32)
	priv.X.FillBytes(x)
	priv.Y.FillBytes(y)
	xs, ys := b64url.EncodeToString(x), b64url.EncodeToString(y)
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + xs + `","y":"` + ys + `"}`))
	return dpopKey{priv: priv, jwk: map[string]any{"kty": "EC", "crv": "P-256", "x": xs, "y": ys}, jkt: sum[:]}
}

// proof signs a DPoP proof with the key; mod adjusts the payload.
func (k dpopKey) proof(t *testing.T, mod func(map[string]any)) string {
	t.Helper()
	payload := map[string]any{"jti": "j1", "htm": "GET", "htu": "https://cdn.example/a.ts", "iat": testNow.Unix()}
	if mod != nil {
		mod(payload)
	}
	h, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": k.jwk})
	p, _ := json.Marshal(payload)
	input := b64url.EncodeToString(h) + "." + b64url.EncodeToString(p)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64url.EncodeToString(sig)
}

func ath(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64url.EncodeToString(sum[:])
}

func dpopRequest(proofs ...string) *cat.Request {
	h := http.Header{}
	for _, p := range proofs {
		h.Add("DPoP", p)
	}
	return &cat.Request{Method: "GET", URI: "https://cdn.example/a.ts", Header: h}
}

func TestDPoPProofs(t *testing.T) {
	k, other := newDPoPKey(t), newDPoPKey(t)
	bound := claimsToken(t, map[any]any{8: map[int64]any{323: k.jkt}})
	windowed := claimsToken(t, map[any]any{8: map[int64]any{323: k.jkt}, 321: map[int64]any{0: 300, 1: 1}})
	cases := []struct {
		name  string
		token string
		req   *cat.Request
		want  error
	}{
		{"a good proof", bound, dpopRequest(k.proof(t, nil)), nil},
		{"no proof", bound, dpopRequest(), cat.ErrProof},
		{"two proofs", bound, dpopRequest(k.proof(t, nil), k.proof(t, nil)), cat.ErrProof},
		{"a proof by another key", bound, dpopRequest(other.proof(t, nil)), cat.ErrProof},
		{"another method", bound, dpopRequest(k.proof(t, func(p map[string]any) { p["htm"] = "POST" })), cat.ErrProof},
		{"another path", bound, dpopRequest(k.proof(t, func(p map[string]any) { p["htu"] = "https://cdn.example/b.ts" })), cat.ErrProof},
		{"htu ignores the query, and is normalized", bound, dpopRequest(k.proof(t, func(p map[string]any) { p["htu"] = "HTTPS://CDN.EXAMPLE:443/a.ts?x=1" })), nil},
		{"iat inside the default 60 s window", bound, dpopRequest(k.proof(t, func(p map[string]any) { p["iat"] = testNow.Unix() - 59 })), nil},
		{"iat exactly at the window's edge", bound, dpopRequest(k.proof(t, func(p map[string]any) { p["iat"] = testNow.Unix() - 60 })), nil},
		{"iat outside it, before", bound, dpopRequest(k.proof(t, func(p map[string]any) { p["iat"] = testNow.Unix() - 61 })), cat.ErrProof},
		{"iat outside it, after", bound, dpopRequest(k.proof(t, func(p map[string]any) { p["iat"] = testNow.Unix() + 61 })), cat.ErrProof},
		{"catdpop's window widens it", windowed, dpopRequest(k.proof(t, func(p map[string]any) { p["iat"] = testNow.Unix() - 200 })), nil},
		{"a wrong ath, even outside the DPoP scheme", bound, dpopRequest(k.proof(t, func(p map[string]any) { p["ath"] = ath("other") })), cat.ErrProof},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validator().ValidateRequest(tc.token, tc.req)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateRequest: %v", err)
				}
				return
			}
			wantKind(t, err, tc.want)
			wantKind(t, err, cat.ErrUnacceptable)
		})
	}
}

// In the DPoP authorization scheme, the proof must carry ath, and the token must be bound (RFC 9449 Section 7).
func TestDPoPScheme(t *testing.T) {
	k := newDPoPKey(t)
	bound := claimsToken(t, map[any]any{8: map[int64]any{323: k.jkt}})
	withAth := dpopRequest(k.proof(t, func(p map[string]any) { p["ath"] = ath(bound) }))
	withAth.ViaDPoPScheme = true
	if _, err := validator().ValidateRequest(bound, withAth); err != nil {
		t.Fatalf("with ath: %v", err)
	}
	noAth := dpopRequest(k.proof(t, nil))
	noAth.ViaDPoPScheme = true
	_, err := validator().ValidateRequest(bound, noAth)
	wantKind(t, err, cat.ErrProof)
	unbound := claimsToken(t, map[any]any{})
	req := dpopRequest(k.proof(t, func(p map[string]any) { p["ath"] = ath(unbound) }))
	req.ViaDPoPScheme = true
	_, err = validator().ValidateRequest(unbound, req)
	wantKind(t, err, cat.ErrProof)
}

// The proof's htu is the URI as received, which still holds a path-style token; catu uses the URI without it.
func TestDPoPHtuUsesTheReceivedURI(t *testing.T) {
	k := newDPoPKey(t)
	token := claimsToken(t, map[any]any{8: map[int64]any{323: k.jkt}})
	req := dpopRequest(k.proof(t, func(p map[string]any) { p["htu"] = "https://cdn.example/a;CAT=x/b.ts" }))
	req.URI, req.ReceivedURI = "https://cdn.example/a/b.ts", "https://cdn.example/a;CAT=x/b.ts"
	if _, err := validator().ValidateRequest(token, req); err != nil {
		t.Fatalf("ValidateRequest: %v", err)
	}
}

func TestDPoPWindowOption(t *testing.T) {
	k := newDPoPKey(t)
	token := claimsToken(t, map[any]any{8: map[int64]any{323: k.jkt}})
	v := validator()
	v.DPoPWindow = 10 * time.Second
	_, err := v.ValidateRequest(token, dpopRequest(k.proof(t, func(p map[string]any) { p["iat"] = testNow.Unix() - 11 })))
	wantKind(t, err, cat.ErrProof)
}

func TestCnfNeedsARequest(t *testing.T) {
	_, err := validator().Validate(claimsToken(t, map[any]any{8: map[int64]any{323: newDPoPKey(t).jkt}}))
	wantKind(t, err, cwt.ErrUnsupported)
}
