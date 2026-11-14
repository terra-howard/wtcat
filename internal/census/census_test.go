package census

import (
	"strings"
	"testing"
)

func TestNormalizedHashIgnoresLineEndings(t *testing.T) {
	lf := NormalizedHash([]byte("package conformance\n\nfunc f() {}\n"))
	crlf := NormalizedHash([]byte("package conformance\r\n\r\nfunc f() {}\r\n"))
	if lf != crlf {
		t.Fatalf("LF and CRLF copies hash differently: %s vs %s", lf, crlf)
	}
	if len(lf) != 64 {
		t.Fatalf("want a 64-character hex SHA-256, got %q", lf)
	}
}

func TestNormalizedHashSeesContentChanges(t *testing.T) {
	a := NormalizedHash([]byte("if got != want {\n"))
	b := NormalizedHash([]byte("if got == want {\n"))
	if a == b {
		t.Fatal("different content produced the same hash")
	}
}

func TestParseManifest(t *testing.T) {
	text := "# protected tests\n\n" +
		strings.Repeat("a", 64) + " conformance/rfc8392_test.go TestA1ClaimsSet\n" +
		strings.Repeat("a", 64) + " conformance/rfc8392_test.go TestA3SignedCWT\n"
	entries, err := ParseManifest(strings.NewReader(text))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	if entries[1].Test != "TestA3SignedCWT" || entries[1].Path != "conformance/rfc8392_test.go" {
		t.Fatalf("unexpected entry: %+v", entries[1])
	}
}

func TestParseManifestRejectsMalformedLines(t *testing.T) {
	cases := map[string]string{
		"too few fields":                  strings.Repeat("a", 64) + " conformance/x_test.go\n",
		"short hash":                      "abc conformance/x_test.go TestX\n",
		"duplicate test":                  strings.Repeat("a", 64) + " conformance/x_test.go TestX\n" + strings.Repeat("a", 64) + " conformance/x_test.go TestX\n",
		"not a test name":                 strings.Repeat("a", 64) + " conformance/x_test.go helper\n",
		"subtest is not a manifest entry": strings.Repeat("a", 64) + " conformance/x_test.go TestX/case\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifest(strings.NewReader(text)); err == nil {
				t.Fatal("want an error, got nil")
			}
		})
	}
}

// events builds a go test -json stream from (test, action) pairs. An empty test name is a package-level event.
func events(pairs ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(pairs); i += 2 {
		test, action := pairs[i], pairs[i+1]
		if test == "" {
			b.WriteString(`{"Action":"` + action + `","Package":"github.com/terra-howard/wtcat/conformance"}` + "\n")
			continue
		}
		b.WriteString(`{"Action":"` + action + `","Package":"github.com/terra-howard/wtcat/conformance","Test":"` + test + `"}` + "\n")
	}
	return b.String()
}

func manifest(tests ...string) []Entry {
	var out []Entry
	for _, name := range tests {
		out = append(out, Entry{Hash: strings.Repeat("a", 64), Path: "conformance/rfc8392_test.go", Test: name})
	}
	return out
}

func goodHashes() map[string]string {
	return map[string]string{"conformance/rfc8392_test.go": strings.Repeat("a", 64)}
}

func TestEvaluateGreen(t *testing.T) {
	stream := events("TestA", "run", "TestA", "pass", "TestB", "run", "TestB", "pass", "", "pass")
	r, err := Evaluate(manifest("TestA", "TestB"), strings.NewReader(stream), goodHashes())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !r.OK() {
		t.Fatalf("want green, got problems: %v", r.Problems)
	}
	if r.Passed != 2 {
		t.Fatalf("want 2 passed, got %d", r.Passed)
	}
}

func TestEvaluateRed(t *testing.T) {
	cases := []struct {
		name   string
		stream string
		hashes map[string]string
		want   string
	}{
		{"failed test", events("TestA", "pass", "TestB", "fail"), goodHashes(), "TestB"},
		{"skipped test", events("TestA", "pass", "TestB", "skip"), goodHashes(), "TestB"},
		{"missing test", events("TestA", "pass"), goodHashes(), "TestB"},
		{"unlisted protected test", events("TestA", "pass", "TestB", "pass", "TestC", "pass"), goodHashes(), "TestC"},
		{"package failure", events("TestA", "pass", "TestB", "pass", "", "fail"), goodHashes(), "package"},
		{"changed file", events("TestA", "pass", "TestB", "pass"), map[string]string{"conformance/rfc8392_test.go": strings.Repeat("b", 64)}, "conformance/rfc8392_test.go"},
		{"missing file", events("TestA", "pass", "TestB", "pass"), map[string]string{}, "conformance/rfc8392_test.go"},
		{"failed subtest", events("TestA", "pass", "TestB/tampered", "fail", "TestB", "pass"), goodHashes(), "TestB/tampered"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Evaluate(manifest("TestA", "TestB"), strings.NewReader(c.stream), c.hashes)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if r.OK() {
				t.Fatal("want red, got green")
			}
			if !strings.Contains(strings.Join(r.Problems, "\n"), c.want) {
				t.Fatalf("want a problem naming %q, got %v", c.want, r.Problems)
			}
		})
	}
}

func TestEvaluateDoesNotBlameThePackageForAFailingTest(t *testing.T) {
	// go test marks the package failed whenever a test in it fails; that is not a separate problem.
	stream := events("TestA", "pass", "TestB", "fail", "", "fail")
	r, err := Evaluate(manifest("TestA", "TestB"), strings.NewReader(stream), goodHashes())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for _, p := range r.Problems {
		if strings.Contains(p, "package") {
			t.Fatalf("a failing test was also reported as a package failure: %v", r.Problems)
		}
	}
}

func TestEvaluateRejectsEmptyManifest(t *testing.T) {
	r, err := Evaluate(nil, strings.NewReader(events("", "pass")), goodHashes())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if r.OK() {
		t.Fatal("an empty manifest protects nothing and must not pass")
	}
}
