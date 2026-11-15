package cathttp

import (
	"strings"
	"testing"
)

// The character predicates, checked for every byte against the sets written out in full: RFC 5234's ALPHA and
// DIGIT, RFC 9110's tchar, and RFC 4648's base64url alphabet.
func TestCharacterPredicates(t *testing.T) {
	const (
		alpha  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		digit  = "0123456789"
		tchar  = alpha + digit + "!#$%&'*+-.^_`|~"
		base64 = alpha + digit + "-_"
		keyc   = "abcdefghijklmnopqrstuvwxyz" + digit + "_-.*"
	)
	in := func(set string, c byte) bool { return strings.IndexByte(set, c) >= 0 }
	for i := range 256 {
		c := byte(i)
		if isAlpha(c) != in(alpha, c) || isDigit(c) != in(digit, c) || isTchar(c) != in(tchar, c) || isBase64URL(c) != in(base64, c) {
			t.Errorf("predicates disagree with the RFC sets at %q", c)
		}
		// A parameter key (RFC 9651 Section 3.1.2) after its first character. The suffix keeps c away from the end,
		// where surrounding whitespace is trimmed, and "_" can continue a key but cannot start a value.
		if _, ok := parseItem("t;a" + string(c) + "_"); ok != in(keyc, c) {
			t.Errorf("parameter key character %q: accepted %v", c, ok)
		}
		// Its first character: a lowercase letter or "*".
		if _, ok := parseItem("t;" + string(c)); ok != in("abcdefghijklmnopqrstuvwxyz*", c) {
			t.Errorf("parameter key start %q: accepted %v", c, ok)
		}
	}
}

func TestParseItemParameterValues(t *testing.T) {
	for value, want := range map[string]bool{
		"1": true, "-1": true, "1.5": true, "-0.25": true, "?1": true, "?0": true, ":AQID:": true, "::": true,
		"@1700000000": true, "@-1": true, `"x"`: true, "tok/x:y": true, "*t": true,
		"?2": false, "?": false, ":AQ!:": false, ":abc": false, "1.": false, "-": false, "@": false, "@1.5": false,
		`"x`: false, "": false, "{": false,
	} {
		if _, ok := parseItem("tok;a=" + value); ok != want {
			t.Errorf("parameter value %q: accepted %v, want %v", value, ok, want)
		}
	}
}

// RFC 9651's limits on integers, decimals and dates (Sections 3.3.1, 3.3.2 and 3.3.7), and its display strings
// (Section 3.3.8): %" then printable ASCII and lowercase %xx escapes that together form UTF-8, then a quote.
func TestParseItemParameterLimitsAndDisplayStrings(t *testing.T) {
	for value, want := range map[string]bool{
		"999999999999999": true, "-999999999999999": true, "1000000000000000": false, "-1000000000000000": false,
		"999999999999.999": true, "1000000000000.5": false, "1.123": true, "1.1234": false,
		"@999999999999999": true, "@1000000000000000": false,
		`%""`: true, `%"plain text"`: true, `%"f%c3%bc%c3%bcr"`: true, `%"%22 and %25"`: true, `%"back\slash"`: true,
		`%"F%C3%BC"`: false, `%"%c3"`: false, `%"%e"`: false, `%"%zz"`: false, `%"unterminated`: false,
		"%\"tab\t\"": false, "%\"del\x7f\"": false, "%\"\xc3\xa9\"": false, `%x`: false, `%`: false,
		`%"na%c3%afve"`: true, `%"%e`: false, `%"%`: false, `%"%z1"`: false, `%"%1z"`: false,
	} {
		if _, ok := parseItem("tok;a=" + value); ok != want {
			t.Errorf("parameter value %q: accepted %v, want %v", value, ok, want)
		}
	}
}

// An sf-string may escape only a quote or a backslash (RFC 9651 Section 4.2.5).
func TestParseItemStringEscapes(t *testing.T) {
	if got, ok := parseItem(`"a\"b\\c"`); !ok || got != `a"b\c` {
		t.Errorf(`parseItem("a\"b\\c") = %q, %v; want a"b\c`, got, ok)
	}
	for _, bad := range []string{`"a\x"`, `"a\`, `"\"`} {
		if got, ok := parseItem(bad); ok {
			t.Errorf("parseItem(%s) = %q, want it refused", bad, got)
		}
	}
}

// Whatever parseItem accepts, written back as an sf-string, parses to the same value.
func FuzzParseItem(f *testing.F) {
	for _, seed := range []string{`"abc"`, `abc;a=1`, `"a\"b";x=?1;y=:AQID:`, `tok;a=%"f%c3%bc"`, `*x/y:z`, ` "x" `} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, field string) {
		value, ok := parseItem(field)
		if !ok {
			return
		}
		quoted := `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
		if again, ok := parseItem(quoted); !ok || again != value {
			t.Fatalf("parseItem(%q) = %q, but its quoted form %q parses to %q, %v", field, value, quoted, again, ok)
		}
	})
}
