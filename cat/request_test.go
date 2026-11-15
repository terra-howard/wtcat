package cat_test

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/fxamacker/cbor/v2"

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

// A header built in code can hold one field under names differing in case. Their lines are joined in the sorted
// order of those names, so the result does not depend on how a map is walked.
func TestCathJoinsFieldLinesInAStableOrder(t *testing.T) {
	token := claimsToken(t, map[any]any{315: map[string]any{"Accept": map[int64]any{0: "a, b, c"}}})
	req := get()
	req.Header = http.Header{"accept": {"c"}, "Accept": {"a", "b"}}
	for i := range 50 {
		if _, err := validator().ValidateRequest(token, req); err != nil {
			t.Fatalf("run %d: ValidateRequest: %v", i, err)
		}
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

func TestValidateRequestChecksCatu(t *testing.T) {
	cases := []struct {
		name string
		catu map[int64]any
		uri  string
		want error
	}{
		{"a path prefix", map[int64]any{3: map[int64]any{1: "/a/"}}, "https://cdn.example/a/b.ts", nil},
		{"outside the path prefix", map[int64]any{3: map[int64]any{1: "/a/"}}, "https://cdn.example/b/x.ts", cat.ErrURI},
		{"dot segments cannot climb out of the prefix", map[int64]any{3: map[int64]any{1: "/public/"}}, "https://cdn.example/public/../private/x", cat.ErrURI},
		{"encoded dot segments cannot either", map[int64]any{3: map[int64]any{1: "/public/"}}, "https://cdn.example/public/%2E%2E/private/x", cat.ErrURI},
		{"the default port is the empty port", map[int64]any{2: map[int64]any{0: ""}}, "https://cdn.example:443/x", nil},
		{"another port is not", map[int64]any{2: map[int64]any{0: ""}}, "https://cdn.example:8443/x", cat.ErrURI},
		{"scheme and host, case-normalized", map[int64]any{0: map[int64]any{0: "https"}, 1: map[int64]any{2: ".example"}}, "HTTPS://CDN.EXAMPLE/x", nil},
		{"an extension", map[int64]any{8: map[int64]any{0: ".ts"}}, "https://cdn.example/a/seg-1.ts", nil},
		{"a query", map[int64]any{4: map[int64]any{0: "a=~"}}, "https://cdn.example/x?a=%7E", nil},
		{"every component must match", map[int64]any{3: map[int64]any{1: "/a/"}, 8: map[int64]any{0: ".mp4"}}, "https://cdn.example/a/b.ts", cat.ErrURI},
		{"a request URI that cannot be parsed", map[int64]any{3: map[int64]any{1: "/"}}, "/relative", cat.ErrURI},
		{"an unknown component", map[int64]any{9: map[int64]any{}}, "https://cdn.example/", cwt.ErrUnsupported},
		{"a negative component", map[int64]any{-1: map[int64]any{}}, "https://cdn.example/", cwt.ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := get()
			req.URI = tc.uri
			_, err := validator().ValidateRequest(claimsToken(t, map[any]any{312: tc.catu}), req)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateRequest: %v", err)
				}
				return
			}
			wantKind(t, err, tc.want)
			if tc.want == cat.ErrURI {
				wantKind(t, err, cat.ErrUnacceptable)
			}
		})
	}
}

func TestCatuNeedsARequest(t *testing.T) {
	_, err := validator().Validate(claimsToken(t, map[any]any{312: map[int64]any{3: map[int64]any{1: "/"}}}))
	wantKind(t, err, cwt.ErrUnsupported)
}

func TestValidateRequestChecksCatnip(t *testing.T) {
	token := claimsToken(t, map[any]any{311: []any{cbor.Tag{Number: 52, Content: []any{24, []byte{192, 0, 2}}}}})
	req := get()
	req.ClientIP = netip.MustParseAddr("192.0.2.9")
	if _, err := validator().ValidateRequest(token, req); err != nil {
		t.Fatalf("an address in the prefix: %v", err)
	}
	req.ClientIP = netip.MustParseAddr("198.51.100.9")
	_, err := validator().ValidateRequest(token, req)
	wantKind(t, err, cat.ErrNetwork)
	wantKind(t, err, cat.ErrUnacceptable)
	_, err = validator().Validate(token)
	wantKind(t, err, cwt.ErrUnsupported)
}
