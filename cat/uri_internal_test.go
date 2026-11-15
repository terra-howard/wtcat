package cat

import (
	"testing"
)

func TestNormalizeURI(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uriParts
	}{
		{"https://cdn.example/a/b.ts", uriParts{scheme: "https", host: "cdn.example", path: "/a/b.ts"}},
		{"HTTPS://CDN.Example/A", uriParts{scheme: "https", host: "cdn.example", path: "/A"}},
		{"https://cdn.example", uriParts{scheme: "https", host: "cdn.example", path: "/"}},
		{"https://cdn.example:443/", uriParts{scheme: "https", host: "cdn.example", path: "/"}},
		{"https://cdn.example:/", uriParts{scheme: "https", host: "cdn.example", path: "/"}},
		{"http://cdn.example:80/", uriParts{scheme: "http", host: "cdn.example", path: "/"}},
		{"http://cdn.example:443/", uriParts{scheme: "http", host: "cdn.example", port: "443", path: "/"}},
		{"https://cdn.example:8080/", uriParts{scheme: "https", host: "cdn.example", port: "8080", path: "/"}},
		{"https://[2001:DB8::1]:8443/x", uriParts{scheme: "https", host: "[2001:db8::1]", port: "8443", path: "/x"}},
		{"https://user@cdn.example/x", uriParts{scheme: "https", host: "cdn.example", path: "/x"}},
		{"https://cdn.example/a/./b/../c", uriParts{scheme: "https", host: "cdn.example", path: "/a/c"}},
		{"https://cdn.example/a/%2e%2E/c", uriParts{scheme: "https", host: "cdn.example", path: "/c"}},
		{"https://cdn.example/../../x", uriParts{scheme: "https", host: "cdn.example", path: "/x"}},
		{"https://cdn.example/%7euser/%2fx%3a", uriParts{scheme: "https", host: "cdn.example", path: "/~user/%2Fx%3A"}},
		{"https://cdn.example/%41%5a%30%2D%2E%5F%7E", uriParts{scheme: "https", host: "cdn.example", path: "/AZ0-._~"}},
		{"https://cdn.example/p?b=%7e&a=%2f", uriParts{scheme: "https", host: "cdn.example", path: "/p", query: "b=~&a=%2F"}},
		{"https://cdn.example/p?", uriParts{scheme: "https", host: "cdn.example", path: "/p"}},
		{"https://cdn.example/p#frag", uriParts{scheme: "https", host: "cdn.example", path: "/p"}},
		{"https://cdn.%45xample/", uriParts{scheme: "https", host: "cdn.example", path: "/"}},
	} {
		got, err := normalizeURI(tc.in)
		if err != nil {
			t.Errorf("normalizeURI(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeURI(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeURIRefuses(t *testing.T) {
	for _, in := range []string{
		"/relative/path",
		"//cdn.example/no-scheme",
		"https:no-authority",
		"https://cdn.example:8o/",
		"https://cdn.example/%zz",
		"https://cdn.example/%4",
		"https://[2001:db8::1/",
		"0000://::",       // found by fuzzing: a digit cannot start a scheme
		"https://a:b:c/",  // a colon in a reg-name
		"https://[v1.x]/", // IPvFuture is not supported
		"https://[]/",
		"https://h st/",
		"",
	} {
		if _, err := normalizeURI(in); err == nil {
			t.Errorf("normalizeURI(%q) succeeded, want an error", in)
		}
	}
}

func TestURIComponents(t *testing.T) {
	for _, tc := range []struct {
		path                              string
		parent, filename, stem, extension string
	}{
		{"/a/b/content.tar.gz", "/a/b", "content.tar.gz", "content.tar", ".gz"},
		{"/content.ts", "", "content.ts", "content", ".ts"},
		{"/a/b/", "/a/b", "", "", ""},
		{"/a/README", "/a", "README", "README", ""},
		{"/a/.hidden", "/a", ".hidden", "", ".hidden"},
		{"/a/.x.y", "/a", ".x.y", "", ".x.y"},
		{"/a/name.", "/a", "name.", "name", "."},
		{"/", "", "", "", ""},
	} {
		p := uriParts{path: tc.path}
		got := [4]string{p.component(5), p.component(6), p.component(7), p.component(8)}
		want := [4]string{tc.parent, tc.filename, tc.stem, tc.extension}
		if got != want {
			t.Errorf("path %q: parent, filename, stem, extension = %q, want %q", tc.path, got, want)
		}
	}
	p := uriParts{scheme: "https", host: "h", port: "8", path: "/p", query: "q"}
	got := [5]string{p.component(0), p.component(1), p.component(2), p.component(3), p.component(4)}
	if want := [5]string{"https", "h", "8", "/p", "q"}; got != want {
		t.Errorf("components 0 to 4 = %q, want %q", got, want)
	}
}

func TestRemoveDotSegmentsRFC3986Examples(t *testing.T) {
	// RFC 3986 Section 5.2.4's two worked examples.
	for in, want := range map[string]string{"/a/b/c/./../../g": "/a/g", "mid/content=5/../6": "mid/6"} {
		if got := removeDotSegments(in); got != want {
			t.Errorf("removeDotSegments(%q) = %q, want %q", in, got, want)
		}
	}
}

// String rebuilds the URI from its normalized parts, for the idempotence property below.
func (p uriParts) String() string {
	s := p.scheme + "://" + p.host
	if p.port != "" {
		s += ":" + p.port
	}
	s += p.path
	if p.query != "" {
		s += "?" + p.query
	}
	return s
}

// Normalizing a normalized URI changes nothing, and nothing panics.
func FuzzNormalizeURI(f *testing.F) {
	for _, seed := range []string{"https://cdn.example/a/./b/../c?x=%7e", "HTTP://[::1]:80/%2e%2E/", "https://u@h:8/p/.x.y", "https://h/a/..", "https://h/./../"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		first, err := normalizeURI(uri)
		if err != nil {
			return
		}
		second, err := normalizeURI(first.String())
		if err != nil {
			t.Fatalf("normalized %q to %q, which does not parse: %v", uri, first.String(), err)
		}
		if second != first {
			t.Fatalf("not idempotent: %q gives %+v, then %+v", uri, first, second)
		}
		for k := int64(0); k <= 8; k++ {
			_ = first.component(k)
		}
	})
}
