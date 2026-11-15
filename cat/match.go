package cat

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"regexp"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Match types (section 4.6.10).
const (
	matchExact      = 0
	matchPrefix     = 1
	matchSuffix     = 2
	matchContains   = 3
	matchRegex      = 4
	matchSHA256     = -1
	matchSHA512x256 = -2
)

// match is one value of a catu or cath claim: a map of match types, every one of which must hold (decision 0017).
type match struct {
	exact, prefix, suffix, contains *string
	regex                           *regexMatch
	sha256, sha512x256              []byte
}

// regexMatch is a POSIX extended regular expression and the values its groups must equal; a nil value is null.
type regexMatch struct {
	re     *regexp.Regexp
	groups []*string
}

// decodeMatch decodes a match map. where names the claim and component, for error messages.
func decodeMatch(value cbor.RawMessage, where string) (*match, error) {
	if len(value) == 0 || majorType(value) == majorTag {
		return nil, malformed("%s: a match is tagged", where)
	}
	var m map[any]cbor.RawMessage
	if err := decMode.Unmarshal(value, &m); err != nil || m == nil {
		return nil, malformed("%s: a match is not a map", where)
	}
	out := &match{}
	for k, v := range m {
		var key int64
		switch kk := k.(type) {
		case uint64:
			if kk > matchRegex {
				return nil, unsupported("%s: match type %d", where, kk)
			}
			key = int64(kk)
		case int64:
			key = kk
		default:
			return nil, malformed("%s: a match type of type %T", where, k)
		}
		if len(v) == 0 || majorType(v) == majorTag {
			return nil, malformed("%s: match type %d is tagged", where, key)
		}
		var err error
		switch key {
		case matchExact:
			out.exact, err = matchText(v, where)
		case matchPrefix:
			out.prefix, err = matchText(v, where)
		case matchSuffix:
			out.suffix, err = matchText(v, where)
		case matchContains:
			out.contains, err = matchText(v, where)
		case matchRegex:
			out.regex, err = decodeRegex(v, where)
		case matchSHA256:
			out.sha256, err = byteString(v, where)
		case matchSHA512x256:
			out.sha512x256, err = byteString(v, where)
		default:
			return nil, unsupported("%s: match type %d", where, key)
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func matchText(v cbor.RawMessage, where string) (*string, error) {
	if len(v) == 0 || majorType(v) != majorText {
		return nil, malformed("%s: a match value is not a text string", where)
	}
	var s string
	if err := decMode.Unmarshal(v, &s); err != nil {
		return nil, malformed("%s: %v", where, err)
	}
	return &s, nil
}

func byteString(v cbor.RawMessage, where string) ([]byte, error) {
	if majorType(v) != majorBytes {
		return nil, malformed("%s: a hash match is not a byte string", where)
	}
	var b []byte
	if err := decMode.Unmarshal(v, &b); err != nil {
		return nil, malformed("%s: %v", where, err)
	}
	return b, nil
}

// decodeRegex decodes [expression, group values...], where a group value is a text string or null.
func decodeRegex(v cbor.RawMessage, where string) (*regexMatch, error) {
	if majorType(v) != majorArray {
		return nil, malformed("%s: a regular-expression match is not an array", where)
	}
	var items []cbor.RawMessage
	if err := decMode.Unmarshal(v, &items); err != nil {
		return nil, malformed("%s: %v", where, err)
	}
	if len(items) == 0 {
		return nil, malformed("%s: a regular-expression match is empty", where)
	}
	expr, err := matchText(items[0], where)
	if err != nil {
		return nil, err
	}
	if err := checkERE(*expr); err != nil {
		return nil, unsupported("%s: regular expression %q: %v", where, *expr, err)
	}
	re, err := regexp.CompilePOSIX(*expr)
	if err != nil {
		return nil, unsupported("%s: regular expression %q: %v", where, *expr, err)
	}
	rm := &regexMatch{re: re}
	for _, item := range items[1:] {
		if len(item) == 1 && item[0] == cborNull {
			rm.groups = append(rm.groups, nil)
			continue
		}
		s, err := matchText(item, where)
		if err != nil {
			return nil, err
		}
		rm.groups = append(rm.groups, s)
	}
	return rm, nil
}

// matches reports whether every match type present holds for s.
func (m *match) matches(s string) bool {
	switch {
	case m.exact != nil && s != *m.exact,
		m.prefix != nil && !strings.HasPrefix(s, *m.prefix),
		m.suffix != nil && !strings.HasSuffix(s, *m.suffix),
		m.contains != nil && !strings.Contains(s, *m.contains),
		m.regex != nil && !m.regex.matches(s):
		return false
	}
	if m.sha256 != nil {
		sum := sha256.Sum256([]byte(s))
		if !bytes.Equal(sum[:], m.sha256) {
			return false
		}
	}
	if m.sha512x256 != nil {
		sum := sha512.Sum512_256([]byte(s))
		if !bytes.Equal(sum[:], m.sha512x256) {
			return false
		}
	}
	return true
}

// matches applies decision 0017: the expression must accept s somewhere, and each group value must equal its group
// in the leftmost-longest match. A null matches anything; a group that did not take part equals no string.
func (r *regexMatch) matches(s string) bool {
	if len(r.groups) > r.re.NumSubexp() {
		return false
	}
	loc := r.re.FindStringSubmatchIndex(s)
	if loc == nil {
		return false
	}
	for i, want := range r.groups {
		if want == nil {
			continue
		}
		start, end := loc[2*(i+1)], loc[2*(i+1)+1]
		if start < 0 || s[start:end] != *want {
			return false
		}
	}
	return true
}

// checkERE refuses the POSIX bracket-expression syntax that Go's engine accepts but reads differently (decision
// 0017): equivalence classes ([=a=]) and collating symbols ([.a.]), which Go takes as literal characters, and
// backslashes, which are literal inside a POSIX bracket expression but escapes in Go's.
func checkERE(expr string) error {
	inBracket := false
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if !inBracket {
			switch c {
			case '\\':
				i++ // skip the escaped character
			case '[':
				inBracket = true
				if i+1 < len(expr) && expr[i+1] == '^' {
					i++
				}
				if i+1 < len(expr) && expr[i+1] == ']' { // a leading ] is a member, not the end
					i++
				}
			}
			continue
		}
		next := byte(0)
		if i+1 < len(expr) {
			next = expr[i+1]
		}
		switch {
		case c == '\\':
			return errors.New("a backslash inside a bracket expression")
		case c == '[' && (next == '=' || next == '.'):
			return errors.New("an equivalence class or collating symbol")
		case c == '[' && next == ':':
			end := strings.Index(expr[i+2:], ":]")
			if end < 0 {
				return errors.New("an unterminated character class")
			}
			i += 2 + end + 1
		case c == ']':
			inBracket = false
		}
	}
	return nil
}
