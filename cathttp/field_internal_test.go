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
	for i := 0; i < 256; i++ {
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
