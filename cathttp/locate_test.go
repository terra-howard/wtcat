package cathttp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/terra-howard/wtcat/cathttp"
)

func request(target string, header map[string][]string) *http.Request {
	r := httptest.NewRequest("GET", target, nil)
	for k, vs := range header {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	return r
}

type found struct {
	text  string
	where cathttp.Location
}

func summary(ls []cathttp.Located) []found {
	out := make([]found, 0, len(ls))
	for _, l := range ls {
		out = append(out, found{l.Text, l.Where})
	}
	return out
}

func TestFindInOrder(t *testing.T) {
	r := request("https://cdn.example/a;CAT=p1/b;CAT=p2?x=1&CAT=q1&CAT=q2", map[string][]string{
		"Cookie":        {"other=1; CAT=c1; CAT=c2"},
		"Authorization": {"Bearer b1"},
	})
	got, err := cathttp.Find(r, cathttp.Options{Bearer: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []found{
		{"p1", cathttp.InPath}, {"p2", cathttp.InPath}, {"q1", cathttp.InQuery}, {"q2", cathttp.InQuery},
		{"c1", cathttp.InCookie}, {"c2", cathttp.InCookie}, {"b1", cathttp.InAuthorization},
	}
	if g := summary(got); len(g) != len(want) {
		t.Fatalf("found %v, want %v", g, want)
	} else {
		for i := range want {
			if g[i] != want[i] {
				t.Errorf("token %d = %v, want %v", i, g[i], want[i])
			}
		}
	}
}

func TestFindRespectsParameterBoundaries(t *testing.T) {
	r := request("https://cdn.example/a;XCAT=no/b?XCAT=no&CATX=no&y=CAT=no&CAT=yes", nil)
	got, err := cathttp.Find(r, cathttp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if g := summary(got); len(g) != 1 || g[0] != (found{"yes", cathttp.InQuery}) {
		t.Fatalf("found %v, want only the form-style parameter named exactly CAT", g)
	}
}

func TestFindKeepsPadding(t *testing.T) {
	got, err := cathttp.Find(request("https://cdn.example/?CAT=abc=&x=1", nil), cathttp.Options{})
	if err != nil || len(got) != 1 || got[0].Text != "abc=" {
		t.Fatalf("found %v, %v; want the padded token abc=", summary(got), err)
	}
}

func TestFindHonoursNames(t *testing.T) {
	r := request("https://cdn.example/?tok=q", map[string][]string{"Cookie": {"c=k"}, "X-Token": {"f"}})
	got, err := cathttp.Find(r, cathttp.Options{Param: "tok", Cookie: "c"})
	if err != nil || len(got) != 2 || got[0].Text != "q" || got[1].Text != "k" {
		t.Fatalf("found %v, %v", summary(got), err)
	}
	got, err = cathttp.Find(r, cathttp.Options{Field: "X-Token"})
	if err != nil || len(got) != 1 || got[0] != (cathttp.Located{Text: "f", Where: cathttp.InField}) {
		t.Fatalf("found %v, %v; want only the configured field", summary(got), err)
	}
}

// If the field is present, only the field is read (section 4.4).
func TestFindFieldIsExclusive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  string
	}{
		{"a token", "eyabc", "eyabc"},
		{"a string", `"0YRDoQ"`, "0YRDoQ"},
		{"a token with parameters", "eyabc;v=1;x", "eyabc"},
		{"a string with surrounding space", ` "0YRD" `, "0YRD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request("https://cdn.example/?CAT=uri", map[string][]string{"Cta-Common-Access-Token": {tc.value}, "Cookie": {"CAT=c"}})
			got, err := cathttp.Find(r, cathttp.Options{})
			if err != nil || len(got) != 1 || got[0] != (cathttp.Located{Text: tc.want, Where: cathttp.InField}) {
				t.Fatalf("found %v, %v; want only %q from the field", summary(got), err, tc.want)
			}
		})
	}
}

// A malformed field yields no token, and other locations are still not read.
func TestFindMalformedField(t *testing.T) {
	for name, values := range map[string][]string{
		"two field lines":               {"a", "b"},
		"a list":                        {"a, b"},
		"an unterminated string":        {`"abc`},
		"a token starting with a digit": {"0YRD"},
		"a bad character":               {"ab{c"},
		"an empty value":                {""},
		"a bad parameter":               {"abc;V=1"},
	} {
		t.Run(name, func(t *testing.T) {
			r := request("https://cdn.example/?CAT=uri", map[string][]string{"Cta-Common-Access-Token": values})
			got, err := cathttp.Find(r, cathttp.Options{})
			if !errors.Is(err, cathttp.ErrField) || len(got) != 0 {
				t.Fatalf("found %v, %v; want no tokens and cathttp.ErrField", summary(got), err)
			}
		})
	}
}

func TestFindAuthorizationSchemes(t *testing.T) {
	bearer := request("https://cdn.example/", map[string][]string{"Authorization": {"Bearer tok"}})
	if got, _ := cathttp.Find(bearer, cathttp.Options{}); len(got) != 0 {
		t.Errorf("Bearer read without being configured: %v", summary(got))
	}
	dpop := request("https://cdn.example/", map[string][]string{"Authorization": {"DPoP tok"}})
	got, err := cathttp.Find(dpop, cathttp.Options{})
	if err != nil || len(got) != 1 || got[0].Where != cathttp.InDPoP {
		t.Errorf("DPoP scheme: found %v, %v; want one token marked InDPoP", summary(got), err)
	}
}

// Section 4.6.10's removal rule: after a sub-delimiter, remove the name through that sub-delimiter; otherwise,
// from the reserved character before the name through the token.
func TestRemoveFromURI(t *testing.T) {
	for _, tc := range []struct{ uri, want string }{
		{"https://h/a;CAT=tok/b", "https://h/a/b"},
		{"https://h/a;CAT=tok;x=1/b", "https://h/a;x=1/b"},
		{"https://h/a;CAT=tok?x=1", "https://h/a?x=1"},
		{"https://h/a?CAT=tok&x=1", "https://h/a?x=1"},
		{"https://h/a?x=1&CAT=tok", "https://h/a?x=1"},
		{"https://h/a?CAT=tok", "https://h/a"},
		{"https://h/a?x=1&CAT=tok&y=2", "https://h/a?x=1&y=2"},
		{"https://h/a?CAT=tok#f", "https://h/a#f"},
	} {
		got, err := cathttp.Find(request(tc.uri, nil), cathttp.Options{})
		if err != nil || len(got) != 1 {
			t.Errorf("%s: found %v, %v", tc.uri, summary(got), err)
			continue
		}
		if out := cathttp.RemoveFromURI(tc.uri, got[0]); out != tc.want {
			t.Errorf("RemoveFromURI(%q) = %q, want %q", tc.uri, out, tc.want)
		}
	}
}

func TestFindIgnoresTheFragment(t *testing.T) {
	for _, target := range []string{"https://cdn.example/a#;CAT=no", "https://cdn.example/a?x=1#&CAT=no"} {
		if got, err := cathttp.Find(request(target, nil), cathttp.Options{}); err != nil || len(got) != 0 {
			t.Errorf("%s: found %v, %v; want nothing", target, summary(got), err)
		}
	}
}
