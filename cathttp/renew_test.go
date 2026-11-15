package cathttp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cathttp"
	"github.com/terra-howard/wtcat/cwt"
)

// renewing is an authorizer whose Validator renews with the test secret under kid r1, so renewed tokens validate.
func renewing() *cathttp.Authorizer {
	a := authorizer()
	a.Validator.Issuance = &cat.Issuance{Key: func(string) (cwt.SigningKey, error) {
		return cwt.SigningKey{Algorithm: cwt.HMAC256x256, KID: []byte("r1"), Material: secret}, nil
	}}
	return a
}

// serve runs the middleware once and reports whether the handler ran.
func serve(t *testing.T, a *cathttp.Authorizer, r *http.Request, handler func(http.ResponseWriter)) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	called := false
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		if handler != nil {
			handler(w)
		}
		w.Write([]byte("content"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec, called
}

func validRenewed(t *testing.T, a *cathttp.Authorizer, text string) {
	t.Helper()
	if _, err := a.Validator.Validate(text); err != nil {
		t.Errorf("the renewed token %q does not validate: %v", text, err)
	}
}

func TestMiddlewareCookieRenewal(t *testing.T) {
	a := renewing()
	tok := token(t, map[any]any{323: map[int64]any{0: 1, 1: 60, 5: []string{"Secure", "HttpOnly"}}})
	rec, called := serve(t, a, request("https://example.com/x?CAT="+tok, nil), nil)
	cookie := rec.Header().Get("Set-Cookie")
	if !called || !strings.HasPrefix(cookie, "CAT=") || !strings.HasSuffix(cookie, "; Secure; HttpOnly") {
		t.Fatalf("handler called %v, Set-Cookie %q", called, cookie)
	}
	validRenewed(t, a, strings.TrimSuffix(strings.TrimPrefix(cookie, "CAT="), "; Secure; HttpOnly"))
}

func TestMiddlewareCookieRenewalDefers(t *testing.T) {
	a := renewing()
	tok := token(t, map[any]any{323: map[int64]any{0: 1, 1: 60, 3: "S"}})
	rec, _ := serve(t, a, request("https://example.com/x?CAT="+tok, nil), func(w http.ResponseWriter) {
		w.Header().Add("Set-Cookie", "S=mine")
	})
	if got := rec.Header().Values("Set-Cookie"); len(got) != 1 || got[0] != "S=mine" {
		t.Errorf("Set-Cookie = %q, want only the handler's own cookie", got)
	}
	bad := token(t, map[any]any{323: map[int64]any{0: 1, 1: 60, 5: []string{"Path=/; Evil=1"}}})
	if rec, _ := serve(t, a, request("https://example.com/x?CAT="+bad, nil), nil); rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("a cookie parameter holding a semicolon was used: %q", rec.Header().Get("Set-Cookie"))
	}
}

func TestMiddlewareHeaderRenewal(t *testing.T) {
	a := renewing()
	tok := token(t, map[any]any{323: map[int64]any{0: 2, 1: 60, 6: []string{"v=1"}}})
	rec, _ := serve(t, a, request("https://example.com/x?CAT="+tok, nil), nil)
	got := rec.Header().Get("CTA-Common-Access-Token")
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `";v=1`) {
		t.Fatalf("header = %q, want a string with parameter v=1", got)
	}
	validRenewed(t, a, strings.TrimSuffix(strings.TrimPrefix(got, `"`), `";v=1`))

	rec, _ = serve(t, a, request("https://example.com/x?CAT="+tok, nil), func(w http.ResponseWriter) {
		w.Header().Set("CTA-Common-Access-Token", "mine")
	})
	if got := rec.Header().Get("CTA-Common-Access-Token"); got != "mine" {
		t.Errorf("the handler's own header was replaced: %q", got)
	}
	bad := token(t, map[any]any{323: map[int64]any{0: 2, 1: 60, 6: []string{"V=1"}}})
	if rec, _ := serve(t, a, request("https://example.com/x?CAT="+bad, nil), nil); rec.Header().Get("CTA-Common-Access-Token") != "" {
		t.Error("an invalid header parameter was used")
	}
}

func TestMiddlewareRedirectRenewal(t *testing.T) {
	a := renewing()
	tok := token(t, map[any]any{323: map[int64]any{0: 3, 1: 60}})
	rec, called := serve(t, a, request("https://example.com/a?x=1&CAT="+tok+"&y=2", nil), nil)
	loc := rec.Header().Get("Location")
	if called || rec.Code != 307 || !strings.HasPrefix(loc, "https://example.com/a?x=1&CAT=") || !strings.HasSuffix(loc, "&y=2") || strings.Contains(loc, tok) {
		t.Fatalf("handler called %v, status %d, Location %q", called, rec.Code, loc)
	}
	validRenewed(t, a, strings.TrimSuffix(strings.TrimPrefix(loc, "https://example.com/a?x=1&CAT="), "&y=2"))
	// Redirect renewal applies only to tokens in the URI.
	rec, called = serve(t, a, request("https://example.com/a", map[string][]string{"Cookie": {"CAT=" + tok}}), nil)
	if !called || rec.Code != 200 || rec.Header().Get("Location") != "" {
		t.Errorf("for a cookie token: handler called %v, status %d", called, rec.Code)
	}
}

// A path-style token is in the URI too, and a redirect keeps the status catr names.
func TestMiddlewareRedirectRenewalOfAPathTokenWithItsStatus(t *testing.T) {
	a := renewing()
	tok := token(t, map[any]any{323: map[int64]any{0: 3, 1: 60, 7: 302}})
	rec, called := serve(t, a, request("https://example.com/a;CAT="+tok+"/b", nil), nil)
	loc := rec.Header().Get("Location")
	if called || rec.Code != 302 || !strings.HasPrefix(loc, "https://example.com/a;CAT=") || !strings.HasSuffix(loc, "/b") || strings.Contains(loc, tok) {
		t.Fatalf("handler called %v, status %d, Location %q", called, rec.Code, loc)
	}
	validRenewed(t, a, strings.TrimSuffix(strings.TrimPrefix(loc, "https://example.com/a;CAT="), "/b"))
}

// Automatic renewal goes back the way the token came (section 4.9.2.1).
func TestMiddlewareAutomaticRenewal(t *testing.T) {
	a := renewing()
	tok := token(t, map[any]any{323: map[int64]any{0: 0, 1: 60}})
	rec, _ := serve(t, a, request("https://example.com/x", map[string][]string{"Cookie": {"CAT=" + tok}}), nil)
	if !strings.HasPrefix(rec.Header().Get("Set-Cookie"), "CAT=") {
		t.Errorf("from a cookie: Set-Cookie %q", rec.Header().Get("Set-Cookie"))
	}
	rec, _ = serve(t, a, request("https://example.com/x", map[string][]string{"Cta-Common-Access-Token": {`"` + tok + `"`}}), nil)
	if !strings.HasPrefix(rec.Header().Get("CTA-Common-Access-Token"), `"`) {
		t.Errorf("from the field: header %q", rec.Header().Get("CTA-Common-Access-Token"))
	}
	rec, _ = serve(t, a, request("https://example.com/x?CAT="+tok, nil), nil)
	if rec.Code != 307 {
		t.Errorf("from the URI: status %d, want a redirect", rec.Code)
	}
}

func TestMiddlewareDoesNotRenewWithoutIssuance(t *testing.T) {
	tok := token(t, map[any]any{323: map[int64]any{0: 1, 1: 60}})
	if rec, _ := serve(t, authorizer(), request("https://example.com/x?CAT="+tok, nil), nil); rec.Header().Get("Set-Cookie") != "" {
		t.Error("renewed without an Issuance")
	}
}

func TestMiddlewareRenewalEdges(t *testing.T) {
	a := renewing()
	for name, tc := range map[string]struct {
		catr       map[int64]any
		wantCookie bool
	}{
		"a space in a cookie parameter":          {map[int64]any{0: 1, 1: 60, 5: []string{"Comment=a b"}}, true},
		"a unit separator in a cookie parameter": {map[int64]any{0: 1, 1: 60, 5: []string{"ab"}}, false},
		"a delete in a cookie parameter":         {map[int64]any{0: 1, 1: 60, 5: []string{"ab"}}, false},
		"a cookie name that is not a token":      {map[int64]any{0: 1, 1: 60, 3: "bad name"}, false},
	} {
		rec, _ := serve(t, a, request("https://example.com/x?CAT="+token(t, map[any]any{323: tc.catr}), nil), nil)
		if got := rec.Header().Get("Set-Cookie") != ""; got != tc.wantCookie {
			t.Errorf("%s: Set-Cookie %q, want a cookie %v", name, rec.Header().Get("Set-Cookie"), tc.wantCookie)
		}
	}
	// With Issuance but no catr, nothing is renewed and nothing breaks.
	if rec, called := serve(t, a, request("https://example.com/x?CAT="+token(t, map[any]any{}), nil), nil); !called || rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("no catr: handler called %v, Set-Cookie %q", called, rec.Header().Get("Set-Cookie"))
	}
	// An automatic renewal from the field uses a header name the catr gives.
	tok := token(t, map[any]any{323: map[int64]any{0: 0, 1: 60, 4: "X-Renewed"}})
	rec, _ := serve(t, a, request("https://example.com/x", map[string][]string{"Cta-Common-Access-Token": {`"` + tok + `"`}}), nil)
	if rec.Header().Get("X-Renewed") == "" {
		t.Errorf("automatic renewal from the field ignored the header name: %v", rec.Header())
	}
}
