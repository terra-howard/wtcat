package cathttp

import (
	"strings"
	"unicode/utf8"
)

// parseItem parses a Structured Field item (RFC 9651 Section 4.2.3) whose bare item is a token or a string, as
// section 4.4.2 requires of the token field, and returns that value. Parameters are parsed, so that a malformed one
// is caught, and then ignored, as section 4.4.2 requires of parameters it does not define.
func parseItem(v string) (string, bool) {
	s := strings.Trim(v, " \t")
	var value string
	var ok bool
	switch {
	case strings.HasPrefix(s, `"`):
		value, s, ok = parseString(s)
	case s != "" && (isAlpha(s[0]) || s[0] == '*'):
		value, s = parseToken(s)
		ok = true
	}
	if !ok {
		return "", false
	}
	for strings.HasPrefix(s, ";") {
		s = strings.TrimLeft(s[1:], " ")
		if s, ok = skipParameter(s); !ok {
			return "", false
		}
	}
	return value, s == ""
}

func isAlpha(c byte) bool { return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' }

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isTchar(c byte) bool {
	return isAlpha(c) || isDigit(c) || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// parseString parses an sf-string: printable ASCII in quotes, with only an escaped quote or backslash allowed.
func parseString(s string) (value, rest string, ok bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			if i+1 >= len(s) || s[i+1] != '"' && s[i+1] != '\\' {
				return "", "", false
			}
			i++
			b.WriteByte(s[i])
		case c == '"':
			return b.String(), s[i+1:], true
		case c < 0x20 || c > 0x7e:
			return "", "", false
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false
}

// parseToken parses an sf-token, whose first character the caller has checked.
func parseToken(s string) (value, rest string) {
	i := 1
	for i < len(s) && (isTchar(s[i]) || s[i] == ':' || s[i] == '/') {
		i++
	}
	return s[:i], s[i:]
}

// skipParameter skips one parameter: a key and an optional bare item of any type RFC 9651 defines (Section 3.1.2).
func skipParameter(s string) (string, bool) {
	if s == "" || !('a' <= s[0] && s[0] <= 'z' || s[0] == '*') {
		return "", false
	}
	i := 1
	for i < len(s) && ('a' <= s[i] && s[i] <= 'z' || isDigit(s[i]) || strings.IndexByte("_-.*", s[i]) >= 0) {
		i++
	}
	s = s[i:]
	if !strings.HasPrefix(s, "=") {
		return s, true // a parameter without a value is true
	}
	s = s[1:]
	switch {
	case s == "":
		return "", false
	case s[0] == '"':
		_, rest, ok := parseString(s)
		return rest, ok
	case strings.HasPrefix(s, `%"`):
		return skipDisplayString(s)
	case isAlpha(s[0]) || s[0] == '*':
		_, rest := parseToken(s)
		return rest, true
	case s[0] == '?':
		if len(s) < 2 || s[1] != '0' && s[1] != '1' {
			return "", false
		}
		return s[2:], true
	case s[0] == ':':
		end := strings.IndexByte(s[1:], ':')
		if end < 0 {
			return "", false
		}
		for _, c := range []byte(s[1 : 1+end]) {
			if !isAlpha(c) && !isDigit(c) && c != '+' && c != '/' && c != '=' {
				return "", false
			}
		}
		return s[end+2:], true
	case s[0] == '@': // a date: an integer, never a decimal (Section 4.2.9)
		return skipNumber(s[1:], false)
	default:
		return skipNumber(s, true)
	}
}

// skipNumber skips an sf-integer, or where allowed an sf-decimal, within RFC 9651's limits (Section 4.2.4): an
// integer has at most 15 digits; a decimal at most 12 before its point and 1 to 3 after it.
func skipNumber(s string, decimal bool) (string, bool) {
	i := 0
	if i < len(s) && s[i] == '-' {
		i++
	}
	start := i
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	digits := i - start
	if digits == 0 {
		return "", false
	}
	if decimal && i < len(s) && s[i] == '.' {
		i++
		fraction := i
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if n := i - fraction; digits > 12 || n == 0 || n > 3 {
			return "", false
		}
		return s[i:], true
	}
	return s[i:], digits <= 15
}

// skipDisplayString skips an sf-displaystring (RFC 9651 Section 4.2.10): %" then printable ASCII, with % only in
// lowercase %xx escapes, then a closing quote. The bytes it stands for must be UTF-8.
func skipDisplayString(s string) (string, bool) {
	var b []byte
	for i := len(`%"`); i < len(s); i++ {
		switch c := s[i]; {
		case c < 0x20 || c > 0x7e:
			return "", false
		case c == '"':
			return s[i+1:], utf8.Valid(b)
		case c == '%':
			if i+2 >= len(s) || !isLowerHex(s[i+1]) || !isLowerHex(s[i+2]) {
				return "", false
			}
			b = append(b, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
		default:
			b = append(b, c)
		}
	}
	return "", false
}

func isLowerHex(c byte) bool { return isDigit(c) || 'a' <= c && c <= 'f' }

// unhex is the value of a digit that isLowerHex accepts.
func unhex(c byte) byte {
	if isDigit(c) {
		return c - '0'
	}
	return c - 'a' + 10
}
