package cat_test

import (
	"errors"
	"testing"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

func over(conn *cat.Connection) *cat.Request {
	req := get()
	req.Connection = conn
	return req
}

func TestCatalpnAndCattpk(t *testing.T) {
	alpn := claimsToken(t, map[any]any{314: [][]byte{[]byte("h2"), []byte("h3")}})
	key := []byte("a DER SubjectPublicKeyInfo")
	tpk := claimsToken(t, map[any]any{319: key})
	cases := []struct {
		name  string
		token string
		req   *cat.Request
		want  error
	}{
		{"a listed ALPN", alpn, over(&cat.Connection{TLS: true, ALPN: "h3"}), nil},
		{"an unlisted ALPN", alpn, over(&cat.Connection{TLS: true, ALPN: "http/1.1"}), cat.ErrConnection},
		{"an ALPN in another case", alpn, over(&cat.Connection{TLS: true, ALPN: "H2"}), cat.ErrConnection},
		{"no ALPN determined", alpn, over(&cat.Connection{TLS: true}), cat.ErrConnection},
		{"not over TLS", alpn, over(&cat.Connection{ALPN: "h2"}), cat.ErrConnection},
		{"catalpn, connection not supplied", alpn, get(), nil},
		{"a matching client key in the chain", tpk, over(&cat.Connection{TLS: true, ClientKeys: [][]byte{[]byte("other"), key}}), nil},
		{"no matching client key", tpk, over(&cat.Connection{TLS: true, ClientKeys: [][]byte{[]byte("other")}}), cat.ErrConnection},
		{"cattpk not over TLS", tpk, over(&cat.Connection{ClientKeys: [][]byte{key}}), cat.ErrConnection},
		{"cattpk, connection not supplied", tpk, get(), nil},
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

func TestCatalpnAndCattpkShapes(t *testing.T) {
	for name, claims := range map[string]map[any]any{
		"catalpn not an array":     {314: []byte("h2")},
		"catalpn empty":            {314: [][]byte{}},
		"catalpn holding text":     {314: []any{"h2"}},
		"cattpk not a byte string": {319: "key"},
	} {
		_, err := validator().ValidateRequest(claimsToken(t, claims), get())
		if !errors.Is(err, cwt.ErrMalformed) {
			t.Errorf("%s: got %v, want cwt.ErrMalformed", name, err)
		}
	}
}
