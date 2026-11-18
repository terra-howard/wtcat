package cat_test

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

// moqtRequest is a MOQT request for an action on a namespace and track, given as text.
func moqtRequest(action int, namespace []string, track *string) *cat.Request {
	m := &cat.MOQTAction{Action: action}
	for _, f := range namespace {
		m.Namespace = append(m.Namespace, []byte(f))
	}
	if track != nil {
		m.Track = []byte(*track)
	}
	return &cat.Request{MOQT: m}
}

func text(s string) *string { return &s }

// TestC4MAuthorizationScopes runs draft-ietf-moq-c4m's "MOQT Authorization Scopes" vectors (decisions 0035 and 0036),
// with a recipient able to revalidate every 60 seconds, so the vector asking for 300 is judged like the others.
func TestC4MAuthorizationScopes(t *testing.T) {
	raw, err := os.ReadFile("testdata/c4m/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keys struct {
			HMAC string `json:"hmac_sha256"`
		} `json:"keys"`
		Scopes []struct {
			ID      string   `json:"id"`
			Reval   *float64 `json:"moqt_reval"`
			CoseB64 string   `json:"cose_b64"`
			Tests   []struct {
				Action    int      `json:"action"`
				Namespace []string `json:"namespace"`
				Track     *string  `json:"track"`
				Expected  bool     `json:"expected"`
			} `json:"authorization_tests"`
		} `json:"moqt_authorization_scopes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	key := cwt.Key{Algorithm: cwt.HMAC256x256, Material: fromHex(t, v.Keys.HMAC)}
	validator := &cat.Validator{
		Keys:            func([]byte) (cat.Key, error) { return cat.Key{Key: key, Issuer: "https://auth.example.com"}, nil },
		Now:             func() time.Time { return time.Unix(1700003600, 0) },
		MinRevalidation: 60 * time.Second, // the moqt_multi_scope vector asks for 300 s (decision 0036)
	}
	if len(v.Scopes) != 5 {
		t.Fatalf("%d scope vectors, want 5", len(v.Scopes))
	}
	for _, vec := range v.Scopes {
		t.Run(vec.ID, func(t *testing.T) {
			for i, tc := range vec.Tests {
				_, err := validator.ValidateRequest(vec.CoseB64, moqtRequest(tc.Action, tc.Namespace, tc.Track))
				switch {
				case tc.Expected && err != nil:
					t.Fatalf("test %d (action %d, %q, %v): %v", i, tc.Action, tc.Namespace, tc.Track, err)
				case !tc.Expected && !errors.Is(err, cat.ErrMOQT):
					t.Fatalf("test %d (action %d, %q, %v): got %v, want cat.ErrMOQT", i, tc.Action, tc.Namespace, tc.Track, err)
				}
			}
		})
	}
}

const moqtKey = -65537

func moqtToken(t *testing.T, value any) string {
	return claimsToken(t, map[any]any{moqtKey: value})
}

func TestMOQTRules(t *testing.T) {
	scope := func(parts ...any) map[any]any { return map[any]any{0: []any{parts}} }
	ns := func(fields ...any) []any { return fields }
	pinned := moqtToken(t, scope([]any{4}, ns([]byte("a"), nil)))
	open := moqtToken(t, scope([]any{4}, ns([]byte("a"))))
	matches := moqtToken(t, scope([]any{4, 7}, ns([]any{1, []byte("ex")}), []any{2, []byte(".m4s")}))
	anyNamespace := moqtToken(t, scope([]any{1}))
	unknownAction := moqtToken(t, scope([]any{99, 4}))
	none := claimsToken(t, map[any]any{1: "issuer"})
	emptyTrack := moqtToken(t, scope([]any{4}, ns([]byte("a")), []byte{}))
	cases := []struct {
		name  string
		token string
		req   *cat.Request
		want  error
	}{
		{"a token without the claim authorizes no MOQT action", none, moqtRequest(4, []string{"a"}, text("t")), cat.ErrMOQT},
		{"an HTTP request is not judged by the claim", pinned, get(), nil},
		{"a nil terminator: the exact length", pinned, moqtRequest(4, []string{"a"}, text("t")), nil},
		{"a nil terminator: a longer namespace", pinned, moqtRequest(4, []string{"a", "b"}, text("t")), cat.ErrMOQT},
		{"without a terminator: a longer namespace", open, moqtRequest(4, []string{"a", "b"}, text("t")), nil},
		{"a namespace shorter than its matches", open, moqtRequest(4, []string{}, text("t")), cat.ErrMOQT},
		{"an unlisted action", open, moqtRequest(6, []string{"a"}, text("t")), cat.ErrMOQT},
		{"prefix and suffix", matches, moqtRequest(7, []string{"example"}, text("seg1.m4s")), nil},
		{"prefix fails", matches, moqtRequest(7, []string{"sample"}, text("seg1.m4s")), cat.ErrMOQT},
		{"suffix fails", matches, moqtRequest(7, []string{"example"}, text("seg1.mp4")), cat.ErrMOQT},
		{"a track match with no track name", matches, moqtRequest(7, []string{"example"}, nil), cat.ErrMOQT},
		{"matching is bytewise, with no case folding", matches, moqtRequest(7, []string{"EXample"}, text("seg1.m4s")), cat.ErrMOQT},
		{"SETUP under a scope with no matches", anyNamespace, moqtRequest(1, nil, nil), nil},
		{"an empty track name matches an empty exact match", emptyTrack, moqtRequest(4, []string{"a"}, text("")), nil},
		{"no track name is not an empty track name", emptyTrack, moqtRequest(4, []string{"a"}, nil), cat.ErrMOQT},
		{"an unknown action code is allowed and never matches", unknownAction, moqtRequest(4, []string{"x"}, text("t")), nil},
		{"an unknown action code is not a request anyone can make", unknownAction, moqtRequest(6, []string{"x"}, text("t")), cat.ErrMOQT},
		{"an unknown key in the claim fails closed", moqtToken(t, map[any]any{0: []any{[]any{[]any{4}}}, 1: true}), moqtRequest(4, []string{"a"}, text("t")), cat.ErrUnacceptable},
		{"an unknown key fails closed for HTTP too", moqtToken(t, map[any]any{0: []any{[]any{[]any{4}}}, 1: true}), get(), cat.ErrUnacceptable},
		{"moqt-reval is refused by a recipient that does not revalidate", claimsToken(t, map[any]any{moqtKey: scope([]any{4}), -65538: 300}), moqtRequest(4, nil, nil), cwt.ErrUnsupported},
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
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMOQTSyntax(t *testing.T) {
	for name, value := range map[string]any{
		"not a map":               []any{1},
		"no key 0":                map[any]any{},
		"scopes not an array":     map[any]any{0: 1},
		"no scopes":               map[any]any{0: []any{}},
		"a scope not an array":    map[any]any{0: []any{4}},
		"an empty scope":          map[any]any{0: []any{[]any{}}},
		"a scope of four":         map[any]any{0: []any{[]any{[]any{4}, []any{}, []byte("t"), 1}}},
		"actions not an array":    map[any]any{0: []any{[]any{4}}},
		"no actions":              map[any]any{0: []any{[]any{[]any{}}}},
		"a text action":           map[any]any{0: []any{[]any{[]any{"subscribe"}}}},
		"nil before the end":      map[any]any{0: []any{[]any{[]any{4}, []any{nil, []byte("a")}}}},
		"an empty namespace list": map[any]any{0: []any{[]any{[]any{4}, []any{}}}},
		"a text match":            map[any]any{0: []any{[]any{[]any{4}, []any{"a"}}}},
		"an integer match":        map[any]any{0: []any{[]any{[]any{4}, []any{7}}}},
		"a tagged claim":          cbor.Tag{Number: 24, Content: []byte{0xa0}},
		"match type 3":            map[any]any{0: []any{[]any{[]any{4}, []any{[]any{3, []byte("a")}}}}},
		"a match of one element":  map[any]any{0: []any{[]any{[]any{4}, []any{[]any{1}}}}},
		"a nil track match":       map[any]any{0: []any{[]any{[]any{4}, []any{[]byte("a")}, nil}}},
		"a text key":              map[any]any{0: []any{[]any{[]any{4}}}, "x": 1},
		"a tag inside":            map[any]any{0: []any{[]any{[]any{4}, []any{cbor.Tag{Number: 24, Content: []byte("a")}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validator().ValidateRequest(moqtToken(t, value), moqtRequest(4, []string{"a"}, text("t")))
			if !errors.Is(err, cwt.ErrMalformed) {
				t.Fatalf("got %v, want malformed", err)
			}
		})
	}
}

func TestMOQTClaimKeyIsConfigurable(t *testing.T) {
	token := claimsToken(t, map[any]any{400: map[any]any{0: []any{[]any{[]any{4}}}}})
	v := validator()
	v.MOQTClaimKey = 400
	if _, err := v.ValidateRequest(token, moqtRequest(4, []string{"a"}, text("t"))); err != nil {
		t.Fatalf("with the claim at 400: %v", err)
	}
	if _, err := validator().ValidateRequest(token, moqtRequest(4, []string{"a"}, text("t"))); !errors.Is(err, cat.ErrMOQT) {
		t.Fatalf("with the default key, the claim at 400 is not the moqt claim: %v", err)
	}
}

// TestMOQTRevalidation checks moqt-reval (decision 0036): reported as Token.Revalidate, and refused when the recipient
// cannot revalidate that often, or at all.
func TestMOQTRevalidation(t *testing.T) {
	token := func(reval any) string {
		return claimsToken(t, map[any]any{moqtKey: map[any]any{0: []any{[]any{[]any{4}}}}, -65538: reval})
	}
	cases := []struct {
		name  string
		reval any
		min   time.Duration
		req   *cat.Request
		want  time.Duration
		err   error
	}{
		{"an interval the recipient can honour", 300, 60 * time.Second, moqtRequest(4, nil, nil), 300 * time.Second, nil},
		{"exactly the recipient's minimum", 60, 60 * time.Second, moqtRequest(4, nil, nil), 60 * time.Second, nil},
		{"a fractional interval", 1.5, time.Second, moqtRequest(4, nil, nil), 1500 * time.Millisecond, nil},
		{"zero means no revalidation", 0, 0, moqtRequest(4, nil, nil), 0, nil},
		{"longer than a Duration holds is clamped", uint64(10_000_000_000), time.Second, moqtRequest(4, nil, nil), time.Duration(math.MaxInt64), nil},
		{"exactly at the limit is clamped", float64(math.MaxInt64) / 1e9, time.Second, moqtRequest(4, nil, nil), time.Duration(math.MaxInt64), nil},
		{"shorter than the recipient can honour", 30, 60 * time.Second, moqtRequest(4, nil, nil), 0, cwt.ErrUnsupported},
		{"a recipient that does not revalidate", 300, 0, moqtRequest(4, nil, nil), 0, cwt.ErrUnsupported},
		{"the same rule over HTTP", 300, 0, get(), 0, cwt.ErrUnsupported},
		{"negative", -1, time.Second, moqtRequest(4, nil, nil), 0, cwt.ErrMalformed},
		{"text", "300", time.Second, moqtRequest(4, nil, nil), 0, cwt.ErrMalformed},
		{"infinite", math.Inf(1), time.Second, moqtRequest(4, nil, nil), 0, cwt.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := validator()
			v.MinRevalidation = tc.min
			tok, err := v.ValidateRequest(token(tc.reval), tc.req)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("got %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateRequest: %v", err)
			}
			if tok.Revalidate != tc.want {
				t.Fatalf("Revalidate = %v, want %v", tok.Revalidate, tc.want)
			}
		})
	}
	tok, err := validator().ValidateRequest(claimsToken(t, map[any]any{1: "issuer"}), get())
	if err != nil || tok.Revalidate != 0 {
		t.Fatalf("without the claim: Revalidate = %v, %v", tok.Revalidate, err)
	}
}
