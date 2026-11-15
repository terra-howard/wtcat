package cat_test

import (
	"errors"
	"testing"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

func get() *cat.Request { return &cat.Request{Method: "GET", URI: "https://cdn.example/a.ts"} }

func TestValidateRequestChecksCatm(t *testing.T) {
	methods := claimsToken(t, map[any]any{313: []string{"GET", "HEAD"}})
	cases := []struct {
		name   string
		text   string
		method string
		want   error
	}{
		{"a listed method", methods, "HEAD", nil},
		{"an unlisted method", methods, "POST", cat.ErrMethod},
		{"a listed method in another case", methods, "get", cat.ErrMethod},
		{"no catm: any method", claimsToken(t, map[any]any{}), "DELETE", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := get()
			req.Method = tc.method
			_, err := validator().ValidateRequest(tc.text, req)
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

// A request claim cannot be checked without a request, so the token is refused, never accepted unchecked.
func TestRequestClaimsNeedARequest(t *testing.T) {
	text := claimsToken(t, map[any]any{313: []string{"GET"}})
	_, err := validator().Validate(text)
	wantKind(t, err, cwt.ErrUnsupported)
	_, err = validator().ValidateRequest(text, nil)
	wantKind(t, err, cwt.ErrUnsupported)
	if errors.Is(err, cat.ErrUnacceptable) {
		t.Error("a token that could not be checked was reported as checked and unacceptable")
	}
}

func TestValidateRequestStillChecksEverythingElse(t *testing.T) {
	_, err := at(validator(), testNow).ValidateRequest(claimsToken(t, map[any]any{4: 1699999999, 313: []string{"GET"}}), get())
	wantKind(t, err, cat.ErrExpired)
}
