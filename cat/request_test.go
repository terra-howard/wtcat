package cat_test

import (
	"errors"
	"net/http"
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

func TestValidateRequestChecksCath(t *testing.T) {
	token := claimsToken(t, map[any]any{315: map[string]any{
		"User-Agent": map[int64]any{3: "Mozilla"},
		"X-Empty":    map[int64]any{0: ""},
	}})
	cases := []struct {
		name   string
		header http.Header
		want   error
	}{
		{"both satisfied", http.Header{"User-Agent": {"Mozilla/5.0"}, "X-Empty": {""}}, nil},
		{"a header name in another case", http.Header{"user-agent": {"Mozilla/5.0"}, "x-empty": {""}}, nil},
		{"a value that does not match", http.Header{"User-Agent": {"curl/8"}, "X-Empty": {""}}, cat.ErrHeader},
		{"a missing header never matches, even an exact empty string", http.Header{"User-Agent": {"Mozilla/5.0"}}, cat.ErrHeader},
		{"field lines are joined before matching", http.Header{"User-Agent": {"Mozilla/5.0"}, "X-Empty": {"", ""}}, cat.ErrHeader},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := get()
			req.Header = tc.header
			_, err := validator().ValidateRequest(token, req)
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

func TestCathJoinsFieldLinesWithACommaAndSpace(t *testing.T) {
	token := claimsToken(t, map[any]any{315: map[string]any{"Accept": map[int64]any{0: "a, b"}}})
	req := get()
	req.Header = http.Header{"Accept": {"a", "b"}}
	if _, err := validator().ValidateRequest(token, req); err != nil {
		t.Fatalf("ValidateRequest: %v", err)
	}
}

func TestCathRefusesNamesThatDifferOnlyInCase(t *testing.T) {
	token := claimsToken(t, map[any]any{315: map[string]any{"Accept": map[int64]any{}, "accept": map[int64]any{}}})
	_, err := validator().ValidateRequest(token, get())
	wantKind(t, err, cwt.ErrMalformed)
}

func TestCathNeedsARequest(t *testing.T) {
	_, err := validator().Validate(claimsToken(t, map[any]any{315: map[string]any{"Accept": map[int64]any{}}}))
	wantKind(t, err, cwt.ErrUnsupported)
}
