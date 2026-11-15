package cathttp

import (
	"strings"
	"testing"
)

// In a target in absolute form, the scheme and authority are skipped, so text there that looks like a parameter is
// never a token; nor is anything in a fragment, even one that starts the path.
func TestFindInTargetSkipsTheAuthorityAndTheFragment(t *testing.T) {
	for target, want := range map[string][]string{
		"http://h;CAT=abc/p":         nil,
		"http://u;CAT=x@h/p?CAT=y":   {"y"},
		"http://h#?CAT=x":            nil,
		"https://h/a;CAT=p#;CAT=f?q": {"p"},
	} {
		var got []string
		for _, l := range findInTarget(target, "CAT") {
			got = append(got, l.Text)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("findInTarget(%q) = %q, want %q", target, got, want)
		}
	}
}

// Every token findInTarget reports lies where it says, right after its parameter name, and RemoveFromURI takes at
// least the name, the "=" and a delimiter out of the target.
func FuzzFindInTarget(f *testing.F) {
	for _, seed := range []string{
		"/a;CAT=x/b?CAT=y&z=1", "/p?a=1&CAT=abc==&CAT=d", "https://h.example:8443/x;CAT=t?q#CAT=f", "/;CAT=", "CAT=x",
		"http://h?CAT=x", "/a;CAT=x,y", "?CAT=x!",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, target string) {
		for _, l := range findInTarget(target, "CAT") {
			if l.Start < 1 || l.Start > l.End || l.End > len(target) {
				t.Fatalf("%q: token at %d to %d is out of bounds", target, l.Start, l.End)
			}
			if !strings.HasPrefix(target[l.Start:], "CAT=") || target[l.Start+len("CAT="):l.End] != l.Text {
				t.Fatalf("%q: token %q at %d to %d is not where it says", target, l.Text, l.Start, l.End)
			}
			if removed := RemoveFromURI(target, l); len(removed) > len(target)-len("CAT=")-1 {
				t.Fatalf("%q: removing %q left %q", target, l.Text, removed)
			}
		}
	})
}
