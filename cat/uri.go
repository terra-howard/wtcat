package cat

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// uriParts is a request URI after normalization (decision 0017): RFC 9110 Section 4.2.3, then RFC 3986 Sections
// 6.2.2 and 6.2.3. Components keep their percent-encodings, except for unreserved characters, which are decoded.
type uriParts struct {
	scheme, host, port, path, query string
}

// The catu components (section 4.6.10).
const (
	componentScheme = iota
	componentHost
	componentPort
	componentPath
	componentQuery
	componentParentPath
	componentFilename
	componentStem
	componentExtension
)

// defaultPorts are the ports RFC 9110 Section 4.2.3 removes in normalization.
var defaultPorts = map[string]string{"http": "80", "https": "443"}

// normalizeURI splits an absolute URI with an authority, as RFC 3986 Appendix B does, and normalizes it.
func normalizeURI(uri string) (uriParts, error) {
	uri, _, _ = strings.Cut(uri, "#") // a fragment is never part of a request
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
	path, query, _ := strings.Cut(rest, "?")

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

// validHost applies RFC 3986 Section 3.2.2, without IPvFuture: an IPv6 address in brackets, with no zone, or a
// non-empty reg-name of unreserved characters, percent-encodings and sub-delimiters. RFC 9110 Section 4.2.1 forbids
// an empty host in http and https URIs.
func validHost(h string) bool {
	if strings.HasPrefix(h, "[") {
		if !strings.HasSuffix(h, "]") {
			return false
		}
		a, err := netip.ParseAddr(h[1 : len(h)-1])
		return err == nil && a.Is6() && a.Zone() == ""
	}
	if h == "" {
		return false
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

// component returns a catu component, componentScheme to componentExtension (section 4.6.10). A filename that
// starts with a dot is all extension.
func (p uriParts) component(key int64) string {
	switch key {
	case componentScheme:
		return p.scheme
	case componentHost:
		return p.host
	case componentPort:
		return p.port
	case componentPath:
		return p.path
	case componentQuery:
		return p.query
	}
	slash := strings.LastIndexByte(p.path, '/')
	filename := p.path[slash+1:]
	stem := filename
	switch dot := strings.LastIndexByte(filename, '.'); {
	case strings.HasPrefix(filename, "."):
		stem = ""
	case dot >= 0:
		stem = filename[:dot]
	}
	switch key {
	case componentParentPath:
		if slash < 0 {
			return ""
		}
		return p.path[:slash]
	case componentFilename:
		return filename
	case componentStem:
		return stem
	default: // componentExtension
		return filename[len(stem):]
	}
}
