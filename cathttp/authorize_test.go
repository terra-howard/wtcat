package cathttp_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cathttp"
	"github.com/terra-howard/wtcat/cwt"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

// token builds an HMAC 256/256 CAT carrying the given claims, deterministically encoded.
func token(t *testing.T, claims map[any]any) string {
	t.Helper()
	em, err := cbor.EncOptions{ShortestFloat: cbor.ShortestFloat16}.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	enc := func(v any) []byte {
		b, err := em.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	protected, payload := enc(map[int64]any{1: 5}), enc(claims)
	h := hmac.New(sha256.New, secret)
	h.Write(enc([]any{"MAC0", protected, []byte{}, payload}))
	return base64.RawURLEncoding.EncodeToString(enc(cbor.Tag{Number: 17, Content: []any{protected, map[int64]any{}, payload, h.Sum(nil)}}))
}

func authorizer() *cathttp.Authorizer {
	return &cathttp.Authorizer{Validator: &cat.Validator{
		Keys: func([]byte) (cat.Key, error) {
			return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: secret}}, nil
		},
		Now: func() time.Time { return time.Unix(1700000000, 0) },
	}}
}

const future, past = 1700000060, 1699999999

func TestAuthorizeJudgesEachTokenWithItselfRemoved(t *testing.T) {
	exact := map[any]any{4: future, 312: map[int64]any{3: map[int64]any{0: "/a/b.ts"}}}
	for name, target := range map[string]string{
		"a path-style token": "https://example.com/a;CAT=" + token(t, exact) + "/b.ts",
		"a form-style token": "https://example.com/a/b.ts?CAT=" + token(t, exact),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := authorizer().Authorize(request(target, nil)); err != nil {
				t.Fatalf("Authorize: %v", err)
			}
		})
	}
}

func TestAuthorizeAnyAcceptableTokenGrants(t *testing.T) {
	target := "https://example.com/x?CAT=" + token(t, map[any]any{4: past}) + "&CAT=" + token(t, map[any]any{4: future})
	if _, err := authorizer().Authorize(request(target, nil)); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
}

// With no acceptable token, the first valid but unacceptable token's error is returned, for catif in phase 4.
func TestAuthorizeReportsTheFirstUnacceptableToken(t *testing.T) {
	target := "https://example.com/x?CAT=AAAA&CAT=" + token(t, map[any]any{4: past}) + "&CAT=" + token(t, map[any]any{5: future})
	_, err := authorizer().Authorize(request(target, nil))
	if !errors.Is(err, cat.ErrExpired) {
		t.Fatalf("got %v, want cat.ErrExpired from the second token", err)
	}
}

func TestAuthorizeFailures(t *testing.T) {
	good := token(t, map[any]any{4: future})
	cases := []struct {
		name   string
		target string
		header map[string][]string
		want   error
	}{
		{"no token", "https://example.com/x", nil, cathttp.ErrNoToken},
		{"a malformed field hides a good URI token", "https://example.com/x?CAT=" + good, map[string][]string{"Cta-Common-Access-Token": {"a, b"}}, cathttp.ErrField},
		{"a DPoP-scheme token", "https://example.com/x", map[string][]string{"Authorization": {"DPoP " + good}}, cwt.ErrUnsupported},
		{"garbage", "https://example.com/x?CAT=AAAA", nil, cwt.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := authorizer().Authorize(request(tc.target, tc.header)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAuthorizeUsesTheFieldAlone(t *testing.T) {
	r := request("https://example.com/x?CAT=AAAA", map[string][]string{"Cta-Common-Access-Token": {`"` + token(t, map[any]any{4: future}) + `"`}})
	if _, err := authorizer().Authorize(r); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
}

func TestAuthorizeTokenLimit(t *testing.T) {
	bad := token(t, map[any]any{4: past})
	target := "https://example.com/x?CAT=" + strings.Repeat(bad+"&CAT=", 6) + token(t, map[any]any{4: future})
	a := authorizer()
	a.MaxTokens = 6
	if _, err := a.Authorize(request(target, nil)); !errors.Is(err, cat.ErrExpired) {
		t.Fatalf("with a limit of 6, the seventh token must not be read: got %v", err)
	}
	a.MaxTokens = 7
	if _, err := a.Authorize(request(target, nil)); err != nil {
		t.Fatalf("with a limit of 7: %v", err)
	}
	a.MaxTokens = 5
	if _, err := a.Authorize(request(target, nil)); err == nil || errors.Is(err, cat.ErrUnacceptable) {
		t.Fatalf("a limit below six is a configuration error, got %v", err)
	}
}

// httptest requests come from 192.0.2.1, which the default client address function reads from RemoteAddr.
func TestAuthorizeClientAddress(t *testing.T) {
	nip := token(t, map[any]any{311: []any{cbor.Tag{Number: 52, Content: []any{24, []byte{192, 0, 2}}}}})
	r := request("https://example.com/x?CAT="+nip, nil)
	if _, err := authorizer().Authorize(r); err != nil {
		t.Fatalf("from 192.0.2.1: %v", err)
	}
	r.RemoteAddr = "198.51.100.7:4000"
	if _, err := authorizer().Authorize(r); !errors.Is(err, cat.ErrNetwork) {
		t.Fatalf("from 198.51.100.7: got %v, want cat.ErrNetwork", err)
	}
}

func TestMiddlewareGrants(t *testing.T) {
	good := token(t, map[any]any{4: future})
	var forwarded *http.Request
	h := authorizer().Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Write([]byte("content"))
	}))
	r := request("https://example.com/x", map[string][]string{"Cta-Common-Access-Token": {`"` + good + `"`}, "Cookie": {"a=1; CAT=x"}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 || forwarded == nil {
		t.Fatalf("status %d, forwarded %v", rec.Code, forwarded != nil)
	}
	if got := rec.Header().Get("Cache-Control"); got != "max-age=60, private" {
		t.Errorf("Cache-Control = %q, want %q", got, "max-age=60, private")
	}
	if forwarded.Header.Get("Cta-Common-Access-Token") != "" {
		t.Error("the token field was forwarded")
	}
	if c, err := forwarded.Cookie("CAT"); err == nil {
		t.Errorf("the token cookie was forwarded: %v", c)
	}
	if c, err := forwarded.Cookie("a"); err != nil || c.Value != "1" {
		t.Errorf("another cookie was lost: %v, %v", c, err)
	}
}

func TestMiddlewareRemovesABearerToken(t *testing.T) {
	a := authorizer()
	a.Options.Bearer = true
	var forwarded *http.Request
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = r }))
	h.ServeHTTP(httptest.NewRecorder(), request("https://example.com/x", map[string][]string{"Authorization": {"Bearer " + token(t, map[any]any{})}}))
	if forwarded == nil || forwarded.Header.Get("Authorization") != "" {
		t.Fatalf("forwarded %v with Authorization %q", forwarded != nil, forwarded.Header.Get("Authorization"))
	}
}

func TestMiddlewareRefuses(t *testing.T) {
	called := false
	h := authorizer().Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	for name, tc := range map[string]struct {
		target  string
		private bool
	}{
		"an expired token": {"https://example.com/x?CAT=" + token(t, map[any]any{4: past}), true},
		"no token":         {"https://example.com/x", false},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, request(tc.target, nil))
			if rec.Code != http.StatusUnauthorized || called {
				t.Fatalf("status %d, handler called %v", rec.Code, called)
			}
			if got := strings.Contains(rec.Header().Get("Cache-Control"), "private"); got != tc.private {
				t.Errorf("Cache-Control private = %v, want %v", got, tc.private)
			}
		})
	}
}

// When Bearer is not configured, an Authorization field is not a token and is forwarded untouched.
func TestMiddlewareKeepsAnUnrelatedAuthorization(t *testing.T) {
	var forwarded *http.Request
	h := authorizer().Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = r }))
	r := request("https://example.com/x?CAT="+token(t, map[any]any{}), map[string][]string{"Authorization": {"Bearer upstream-credential"}})
	h.ServeHTTP(httptest.NewRecorder(), r)
	if forwarded == nil || forwarded.Header.Get("Authorization") != "Bearer upstream-credential" {
		t.Fatalf("forwarded %v; the unrelated Authorization field must pass through", forwarded != nil)
	}
}
