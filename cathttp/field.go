package cathttp

import "strings"

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

// skipParameter skips one parameter: a key and an optional bare item of any type RFC 9651 defines here.
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
	default: // an integer, a decimal or a date
		j := 0
		if s[0] == '@' {
			j++
		}
		if j < len(s) && s[j] == '-' {
			j++
		}
		digits := j
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		if j == digits {
			return "", false
		}
		if j < len(s) && s[j] == '.' && s[0] != '@' {
			j++
			fraction := j
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			if j == fraction {
				return "", false
			}
		}
		return s[j:], true
	}
}
