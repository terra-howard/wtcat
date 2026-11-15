package cat

import (
	"errors"
	"fmt"
	"strings"
)

// uriParts is a request URI after normalization (decision 0017): RFC 9110 Section 4.2.3, then RFC 3986 Sections
// 6.2.2 and 6.2.3. Components keep their percent-encodings, except for unreserved characters, which are decoded.
type uriParts struct {
	scheme, host, port, path, query string
}

// defaultPorts are the ports RFC 9110 Section 4.2.3 removes in normalization.
var defaultPorts = map[string]string{"http": "80", "https": "443"}

// normalizeURI splits an absolute URI with an authority, as RFC 3986 Appendix B does, and normalizes it.
func normalizeURI(uri string) (uriParts, error) {
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		uri = uri[:i] // a fragment is never part of a request
	}
	colon := strings.IndexByte(uri, ':')
	if colon <= 0 || strings.ContainsAny(uri[:colon], "/?") {
		return uriParts{}, errors.New("not an absolute URI")
	}
	scheme, rest := strings.ToLower(uri[:colon]), uri[colon+1:]
	if !validScheme(scheme) {
		return uriParts{}, fmt.Errorf("scheme %q is not RFC 3986 syntax", scheme)
	}
	if !strings.HasPrefix(rest, "//") {
		return uriParts{}, errors.New("no authority")
	}
	rest = rest[2:]
	end := strings.IndexAny(rest, "/?")
	if end < 0 {
		end = len(rest)
	}
	authority, rest := rest[:end], rest[end:]
	path, query := rest, ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		path, query = rest[:i], rest[i+1:]
	}

	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:] // userinfo is not a catu component
	}
	host, port := authority, ""
	if strings.HasPrefix(host, "[") {
		closing := strings.IndexByte(host, ']')
		if closing < 0 {
			return uriParts{}, errors.New("unterminated IP literal")
		}
		host, port = authority[:closing+1], authority[closing+1:]
		if port != "" && port[0] != ':' {
			return uriParts{}, errors.New("text after an IP literal")
		}
		port = strings.TrimPrefix(port, ":")
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host, port = host[:i], host[i+1:]
	}
	if !validHost(host) {
		return uriParts{}, fmt.Errorf("host %q is not RFC 3986 syntax", host)
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return uriParts{}, fmt.Errorf("port %q is not a number", port)
		}
	}
	if port == defaultPorts[scheme] {
		port = ""
	}

	var err error
	if host, err = normalizePercent(host); err != nil {
		return uriParts{}, err
	}
	if path, err = normalizePercent(path); err != nil {
		return uriParts{}, err
	}
	if query, err = normalizePercent(query); err != nil {
		return uriParts{}, err
	}
	path = removeDotSegments(path)
	if path == "" {
		path = "/"
	}
	return uriParts{scheme: scheme, host: strings.ToLower(host), port: port, path: path, query: query}, nil
}

// normalizePercent decodes percent-encoded unreserved characters and uppercases the hexadecimal digits of every
// other percent-encoding (RFC 3986 Sections 6.2.2.1 and 6.2.2.2).
func normalizePercent(s string) (string, error) {
	if !strings.Contains(s, "%") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
			return "", errors.New("a percent sign not followed by two hexadecimal digits")
		}
		c := unhex(s[i+1])<<4 | unhex(s[i+2])
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteString(strings.ToUpper(s[i : i+3]))
		}
		i += 2
	}
	return b.String(), nil
}

// validScheme applies RFC 3986 Section 3.1: a letter, then letters, digits, "+", "-" or ".".
func validScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := 'a' <= c && c <= 'z'
		if !letter && (i == 0 || !('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.')) {
			return false
		}
	}
	return s != ""
}

// validHost applies RFC 3986 Section 3.2.2, without IPvFuture: an IP literal of hexadecimal digits, colons and
// dots in brackets, or a reg-name of unreserved characters, percent-encodings and sub-delimiters.
func validHost(h string) bool {
	if strings.HasPrefix(h, "[") {
		if len(h) < 3 || h[len(h)-1] != ']' {
			return false
		}
		for i := 1; i < len(h)-1; i++ {
			if c := h[i]; !isHex(c) && c != ':' && c != '.' {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(h); i++ {
		if c := h[i]; !isUnreserved(c) && c != '%' && !strings.ContainsRune("!$&'()*+,;=", rune(c)) {
			return false
		}
	}
	return true
}

func isHex(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' }

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

func isUnreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

// removeDotSegments is RFC 3986 Section 5.2.4's algorithm.
func removeDotSegments(in string) string {
	var out []string
	for in != "" {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "/..":
			in = "/"
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case in == "." || in == "..":
			in = ""
		default:
			start := 0
			if in[0] == '/' {
				start = 1
			}
			end := strings.IndexByte(in[start:], '/')
			if end < 0 {
				end = len(in)
			} else {
				end += start
			}
			out = append(out, in[:end])
			in = in[end:]
		}
	}
	return strings.Join(out, "")
}

// component returns catu component key 0 to 8 (section 4.6.10).
func (p uriParts) component(key int64) string {
	switch key {
	case 0:
		return p.scheme
	case 1:
		return p.host
	case 2:
		return p.port
	case 3:
		return p.path
	case 4:
		return p.query
	}
	slash := strings.LastIndexByte(p.path, '/')
	filename := p.path[slash+1:]
	stem := filename
	if dot := strings.LastIndexByte(filename, '.'); strings.HasPrefix(filename, ".") {
		stem = ""
	} else if dot >= 0 {
		stem = filename[:dot]
	}
	switch key {
	case 5:
		if slash < 0 {
			return ""
		}
		return p.path[:slash]
	case 6:
		return filename
	case 7:
		return stem
	default: // 8
		return filename[len(stem):]
	}
}
