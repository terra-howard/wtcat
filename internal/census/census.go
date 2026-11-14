// Package census checks that every protected test still exists, ran, passed and is unchanged.
//
// The rules are set by docs/decisions/0003-protected-tests.md.
package census

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Entry is one line of the manifest: a protected test and the hash of the file it lives in.
type Entry struct {
	Hash string // SHA-256 of the file, line endings normalised to LF, lower-case hex
	Path string // file path relative to the repository root, with forward slashes
	Test string // top-level test function name, for example TestA3SignedCWT
}

// Report is the outcome of one census.
type Report struct {
	Passed   int      // protected tests that ran and passed
	Problems []string // every reason the census is red; empty means green
}

// OK reports whether the census is green.
func (r Report) OK() bool { return len(r.Problems) == 0 }

// NormalizedHash returns the lower-case hex SHA-256 of data with CRLF line endings converted to LF, so a file
// hashes the same on every platform.
func NormalizedHash(data []byte) string {
	sum := sha256.Sum256(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")))
	return hex.EncodeToString(sum[:])
}

// ParseManifest reads a manifest. Each non-blank line that does not start with # holds three fields separated by
// spaces: hash, path, test name.
func ParseManifest(r io.Reader) ([]Entry, error) {
	var entries []Entry
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		f := strings.Fields(text)
		if len(f) != 3 {
			return nil, fmt.Errorf("manifest line %d: want hash, path and test name, got %d fields", line, len(f))
		}
		e := Entry{Hash: f[0], Path: f[1], Test: f[2]}
		if !isHexSHA256(e.Hash) {
			return nil, fmt.Errorf("manifest line %d: %q is not a lower-case hex SHA-256", line, e.Hash)
		}
		if !strings.HasPrefix(e.Test, "Test") || strings.Contains(e.Test, "/") {
			return nil, fmt.Errorf("manifest line %d: %q is not a top-level test name", line, e.Test)
		}
		if seen[e.Test] {
			return nil, fmt.Errorf("manifest line %d: %s is listed twice", line, e.Test)
		}
		seen[e.Test] = true
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	return entries, nil
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// event is the part of a go test -json event the census reads. See go doc cmd/test2json.
type event struct {
	Action  string
	Package string
	Test    string
}

// Evaluate judges a go test -json event stream for the protected package against the manifest. fileHashes maps
// each manifest path that exists to its NormalizedHash; a path absent from the map is treated as missing.
func Evaluate(entries []Entry, events io.Reader, fileHashes map[string]string) (Report, error) {
	var r Report
	final := map[string]string{} // test name, including subtests, to its last pass, fail or skip
	var packageFailures []string
	testFailedIn := map[string]bool{} // packages where at least one test failed or was skipped

	dec := json.NewDecoder(events)
	for {
		var ev event
		err := dec.Decode(&ev)
		if err == io.EOF {
			break
		}
		if err != nil {
			return Report{}, fmt.Errorf("reading go test -json output: %w", err)
		}
		switch ev.Action {
		case "pass", "fail", "skip":
			if ev.Test == "" {
				if ev.Action == "fail" {
					packageFailures = append(packageFailures, ev.Package)
				}
				continue
			}
			final[ev.Test] = ev.Action
			if ev.Action != "pass" {
				testFailedIn[ev.Package] = true
			}
		}
	}

	if len(entries) == 0 {
		r.Problems = append(r.Problems, "the manifest lists no protected tests, so it protects nothing")
	}
	for _, pkg := range packageFailures {
		// go test also marks a package failed when one of its tests fails; that is reported per test below.
		if !testFailedIn[pkg] {
			r.Problems = append(r.Problems, fmt.Sprintf("package %s failed as a whole (a build failure, or a test binary that did not finish)", pkg))
		}
	}

	listed := map[string]bool{}
	for _, e := range entries {
		listed[e.Test] = true
		switch final[e.Test] {
		case "pass":
			r.Passed++
		case "fail":
			r.Problems = append(r.Problems, fmt.Sprintf("protected test %s failed", e.Test))
		case "skip":
			r.Problems = append(r.Problems, fmt.Sprintf("protected test %s was skipped", e.Test))
		default:
			r.Problems = append(r.Problems, fmt.Sprintf("protected test %s did not run (deleted, renamed, or never reached)", e.Test))
		}
	}

	names := make([]string, 0, len(final))
	for name := range final {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		root, _, isSub := strings.Cut(name, "/")
		switch {
		case !listed[root]:
			if !isSub {
				r.Problems = append(r.Problems, fmt.Sprintf("test %s is in the protected package but not in the manifest", name))
			}
		case isSub && final[name] == "fail":
			r.Problems = append(r.Problems, fmt.Sprintf("protected subtest %s failed", name))
		case isSub && final[name] == "skip":
			r.Problems = append(r.Problems, fmt.Sprintf("protected subtest %s was skipped", name))
		}
	}

	checked := map[string]bool{}
	for _, e := range entries {
		if checked[e.Path] {
			continue
		}
		checked[e.Path] = true
		got, ok := fileHashes[e.Path]
		switch {
		case !ok:
			r.Problems = append(r.Problems, fmt.Sprintf("protected file %s is missing", e.Path))
		case got != e.Hash:
			r.Problems = append(r.Problems, fmt.Sprintf("protected file %s has changed since the manifest was written", e.Path))
		}
	}

	if r.OK() && r.Passed != len(entries) {
		r.Problems = append(r.Problems, fmt.Sprintf("%d protected tests passed, but the manifest lists %d", r.Passed, len(entries)))
	}
	return r, nil
}
