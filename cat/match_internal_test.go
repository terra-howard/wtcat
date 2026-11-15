package cat

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

func mustMatch(t *testing.T, m map[int64]any) *match {
	t.Helper()
	got, err := decodeMatch(enc(t, m), "test")
	if err != nil {
		t.Fatalf("decodeMatch(%v): %v", m, err)
	}
	return got
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMatchTypes(t *testing.T) {
	sha256abc := hexBytes(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	sha512x256abc := hexBytes(t, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
	cases := []struct {
		name  string
		match map[int64]any
		in    string
		want  bool
	}{
		{"exact", map[int64]any{0: "/a/b.ts"}, "/a/b.ts", true},
		{"exact, longer input", map[int64]any{0: "/a/b"}, "/a/b.ts", false},
		{"exact is case-sensitive", map[int64]any{0: "/A"}, "/a", false},
		{"prefix", map[int64]any{1: "/a/"}, "/a/b.ts", true},
		{"prefix, not at the start", map[int64]any{1: "a/"}, "/a/b.ts", false},
		{"suffix", map[int64]any{2: ".ts"}, "/a/b.ts", true},
		{"suffix, not at the end", map[int64]any{2: ".t"}, "/a/b.ts", false},
		{"contains", map[int64]any{3: "a/b"}, "/a/b.ts", true},
		{"contains, absent", map[int64]any{3: "a/c"}, "/a/b.ts", false},
		{"every type present must hold", map[int64]any{1: "/a", 2: ".ts"}, "/a/b.ts", true},
		{"one of two fails", map[int64]any{1: "/a", 2: ".mp4"}, "/a/b.ts", false},
		{"an empty match map matches anything", map[int64]any{}, "anything", true},
		{"SHA-256", map[int64]any{-1: sha256abc}, "abc", true},
		{"SHA-256, other input", map[int64]any{-1: sha256abc}, "abd", false},
		{"SHA-512/256", map[int64]any{-2: sha512x256abc}, "abc", true},
		{"SHA-512/256 is not truncated SHA-512", map[int64]any{-2: sha256abc}, "abc", false},
		{"regex, unanchored", map[int64]any{4: []any{"b+"}}, "abbbc", true},
		{"regex, anchored", map[int64]any{4: []any{"^b"}}, "abc", false},
		{"regex is case-sensitive", map[int64]any{4: []any{"B"}}, "abc", false},
		{"regex groups", map[int64]any{4: []any{"([a-z]+)/([0-9]+)", "abc", nil}}, "x/abc/123/", true},
		{"regex group mismatch", map[int64]any{4: []any{"([a-z]+)/([0-9]+)", "abd", nil}}, "x/abc/123/", false},
		{"two regex groups", map[int64]any{4: []any{"([a-z]+)/([0-9]+)", "abc", "123"}}, "x/abc/123/", true},
		{"the second regex group mismatches", map[int64]any{4: []any{"([a-z]+)/([0-9]+)", "abc", "124"}}, "x/abc/123/", false},
		{"more values than groups, even null", map[int64]any{4: []any{"(a)", "a", nil}}, "a", false},
		{"a group that did not take part equals no string", map[int64]any{4: []any{"(a)|(b)", nil, ""}}, "a", false},
		{"a group that did not take part, compared with null", map[int64]any{4: []any{"(a)|(b)", "a", nil}}, "a", true},
		{"leftmost-longest, as POSIX requires", map[int64]any{4: []any{"(a|ab)", "ab"}}, "abc", true},
		{"bracket character class", map[int64]any{4: []any{"^[[:digit:]]+$"}}, "123", true},
		{"a dot inside brackets is literal", map[int64]any{4: []any{"^[.]$"}}, ".", true},
		{"a dot inside brackets is not a wildcard", map[int64]any{4: []any{"^[.]$"}}, "a", false},
		{"a leading ] inside brackets is literal", map[int64]any{4: []any{"^[]a]$"}}, "]", true},
		{"a leading ] after ^ inside brackets is literal", map[int64]any{4: []any{"^[^]a]$"}}, "]", false},
		{"an escaped [ outside brackets", map[int64]any{4: []any{`^\[=$`}}, "[=", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustMatch(t, tc.match).matches(tc.in); got != tc.want {
				t.Fatalf("matches(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestDecodeMatchRefuses(t *testing.T) {
	cases := []struct {
		name  string
		value []byte
		want  error
	}{
		{"not a map", enc(t, []any{}), cwt.ErrMalformed},
		{"tagged", enc(t, cbor.Tag{Number: 1000, Content: map[int64]any{}}), cwt.ErrMalformed},
		{"a text key", enc(t, map[string]any{"exact": "a"}), cwt.ErrMalformed},
		{"exact not text", enc(t, map[int64]any{0: 1}), cwt.ErrMalformed},
		{"exact tagged", enc(t, map[int64]any{0: cbor.Tag{Number: 1000, Content: "a"}}), cwt.ErrMalformed},
		{"SHA-256 not bytes", enc(t, map[int64]any{-1: "abc"}), cwt.ErrMalformed},
		{"regex not an array", enc(t, map[int64]any{4: "a"}), cwt.ErrMalformed},
		{"regex an empty array", enc(t, map[int64]any{4: []any{}}), cwt.ErrMalformed},
		{"regex expression not text", enc(t, map[int64]any{4: []any{1}}), cwt.ErrMalformed},
		{"regex expression null", enc(t, map[int64]any{4: []any{nil}}), cwt.ErrMalformed},
		{"regex group value an integer", enc(t, map[int64]any{4: []any{"(a)", 1}}), cwt.ErrMalformed},
		{"regex that does not compile", enc(t, map[int64]any{4: []any{"(a"}}), cwt.ErrUnsupported},
		{"POSIX equivalence class, which Go reads differently", enc(t, map[int64]any{4: []any{"[[=a=]]"}}), cwt.ErrUnsupported},
		{"POSIX collating symbol, which Go reads differently", enc(t, map[int64]any{4: []any{"[[.a.]]"}}), cwt.ErrUnsupported},
		{"a backslash inside brackets, literal in POSIX but an escape in Go", enc(t, map[int64]any{4: []any{`[\]]`}}), cwt.ErrUnsupported},
		{"an unterminated character class", enc(t, map[int64]any{4: []any{"[[:digit"}}), cwt.ErrUnsupported},
		{"an equivalence class after a leading ]", enc(t, map[int64]any{4: []any{"[][=a=]]"}}), cwt.ErrUnsupported},
		{"an equivalence class after a character class", enc(t, map[int64]any{4: []any{"[[:digit:][=a=]]"}}), cwt.ErrUnsupported},
		{"a bracket opened at the very end", enc(t, map[int64]any{4: []any{"a["}}), cwt.ErrUnsupported},
		{"a negated bracket opened at the very end", enc(t, map[int64]any{4: []any{"a[^"}}), cwt.ErrUnsupported},
		{"an equivalence class after a leading ^]", enc(t, map[int64]any{4: []any{"[^][=a=]]"}}), cwt.ErrUnsupported},
		{"a match type key too large for int64, which must not wrap to -1", enc(t, map[uint64]any{1<<64 - 1: []byte{}}), cwt.ErrUnsupported},
		{"Perl's \\d, outside POSIX ERE", enc(t, map[int64]any{4: []any{`\d`}}), cwt.ErrUnsupported},
		{"an unknown match type", enc(t, map[int64]any{5: "a"}), cwt.ErrUnsupported},
		{"a private match type", enc(t, map[int64]any{-25: "a"}), cwt.ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeMatch(tc.value, "test"); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want an error wrapping %v", err, tc.want)
			}
		})
	}
}
