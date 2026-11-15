package cathttp_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cathttp"
	"github.com/terra-howard/wtcat/cwt"
)

// Protect a handler: a request with an acceptable CAT reaches it, and any other is answered 401. Every response
// to a request that carried a token is marked private, so shared caches do not store it.
func ExampleAuthorizer_Middleware() {
	secret := []byte("0123456789abcdef0123456789abcdef")
	auth := &cathttp.Authorizer{Validator: &cat.Validator{
		Keys: func(kid []byte) (cat.Key, error) {
			if string(kid) != "k1" {
				return cat.Key{}, errors.New("unknown key")
			}
			return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: secret}, Issuer: "issuer.example"}, nil
		},
	}}
	protected := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "content")
	}))

	// A token from issuer.example for paths under /videos/ (catu 312: path 3, prefix match 1). It is issued here
	// only to keep the example self-contained; normally the issuer makes it.
	claims, _ := cbor.Marshal(map[int64]any{1: "issuer.example", 312: map[int64]any{3: map[int64]any{1: "/videos/"}}})
	raw, _ := cwt.Issue(claims, cwt.SigningKey{Algorithm: cwt.HMAC256x256, KID: []byte("k1"), Material: secret})
	token := base64.RawURLEncoding.EncodeToString(raw)

	for _, target := range []string{"/videos/intro.mp4?CAT=" + token, "/videos/intro.mp4", "/admin?CAT=" + token} {
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://cdn.example"+target, nil))
		fmt.Printf("%d %q\n", rec.Code, rec.Header().Get("Cache-Control"))
	}
	// Output:
	// 200 "private"
	// 401 ""
	// 401 "private"
}
