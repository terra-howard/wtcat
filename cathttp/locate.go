package cathttp

import (
	"errors"
	"net/http"
	"strings"
)

// Location says where a token was found (CTA-5007-B section 4.4).
type Location int

// Locations, in the order section 4.4 processes them after the field.
const (
	InField         Location = iota // the CTA-Common-Access-Token field, or the configured one
	InPath                          // a path-style parameter, ;CAT=
	InQuery                         // a form-style parameter, ?CAT= or &CAT=
	InCookie                        // a cookie
	InAuthorization                 // Authorization: Bearer
	InDPoP                          // Authorization: DPoP (RFC 9449 Section 7), checked with its proof
)

// Located is a token and where it was found. For InPath and InQuery, Start is the offset of the parameter name and
// End the offset just past the token, both in the request target Find scanned.
type Located struct {
	Text       string
	Where      Location
	Start, End int
}

// Options names the places tokens are looked for. Empty names take section 4.4's defaults.
type Options struct {
	Field  string // default "CTA-Common-Access-Token"
	Param  string // path-style and form-style parameter name; default "CAT"
	Cookie string // default "CAT"
	Bearer bool   // also read Authorization: Bearer
}

// DefaultField is the field section 4.4.2 defines.
const DefaultField = "CTA-Common-Access-Token"

// ErrField means the token field is present but is not a single Structured Field item. Section 4.4 then forbids
// reading any other location, so no token is found.
var ErrField = errors.New("cathttp: the token field is not a single token or string")

func (o Options) withDefaults() Options {
	if o.Field == "" {
		o.Field = DefaultField
	}
	if o.Param == "" {
		o.Param = "CAT"
	}
	if o.Cookie == "" {
		o.Cookie = "CAT"
	}
	return o
}

// Target returns the request target Find scans and RemoveFromURI edits: the request line's target as received, or
// the URL's request URI for a request built in code.
func Target(r *http.Request) string {
	if r.RequestURI != "" {
		return r.RequestURI
	}
	return r.URL.RequestURI()
}

// Find returns the tokens in a request in section 4.4's order: only the field, if present; otherwise path-style
// then form-style parameters left to right, cookies left to right, then the authorization field.
func Find(r *http.Request, o Options) ([]Located, error) {
	o = o.withDefaults()
	if values := r.Header.Values(o.Field); len(values) > 0 {
		if len(values) != 1 {
			return nil, ErrField
		}
		text, ok := parseItem(values[0])
		if !ok {
			return nil, ErrField
		}
		return []Located{{Text: text, Where: InField}}, nil
	}
	out := findInTarget(Target(r), o.Param)
	for _, c := range r.Cookies() {
		if c.Name == o.Cookie {
			out = append(out, Located{Text: c.Value, Where: InCookie})
		}
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		scheme, token, _ := strings.Cut(auth, " ")
		token = strings.TrimSpace(token)
		switch {
		case strings.EqualFold(scheme, "Bearer") && o.Bearer && token != "":
			out = append(out, Located{Text: token, Where: InAuthorization})
		case strings.EqualFold(scheme, "DPoP") && token != "":
			out = append(out, Located{Text: token, Where: InDPoP})
		}
	}
	return out, nil
}

// findInTarget finds path-style parameters (;name=) in the path and form-style parameters (?name= or &name=) in the
// query (RFC 6570 Sections 3.2.7 to 3.2.9), left to right.
func findInTarget(target, name string) []Located {
	pathStart := 0
	if !strings.HasPrefix(target, "/") { // absolute form: skip the scheme and authority
		if i := strings.Index(target, "://"); i >= 0 {
			pathStart = i + 3
			if j := strings.IndexAny(target[pathStart:], "/?#"); j >= 0 {
				pathStart += j
			} else {
				pathStart = len(target)
			}
		}
	}
	end := len(target) // a fragment, never sent by clients, is not searched
	if i := strings.IndexByte(target[pathStart:], '#'); i >= 0 {
		end = pathStart + i
	}
	queryStart := end
	if i := strings.IndexByte(target[pathStart:end], '?'); i >= 0 {
		queryStart = pathStart + i
	}
	var out []Located
	scan := func(from, to int, delims string) {
		for i := from; i < to; i++ {
			if strings.IndexByte(delims, target[i]) < 0 || !strings.HasPrefix(target[i+1:to], name+"=") {
				continue
			}
			start := i + 1
			valueStart := start + len(name) + 1
			v := valueStart
			for v < to && isBase64URL(target[v]) {
				v++
			}
			for pad := 0; pad < 2 && v < to && target[v] == '='; pad++ {
				v++
			}
			where := InPath
			if delims != ";" {
				where = InQuery
			}
			out = append(out, Located{Text: target[valueStart:v], Where: where, Start: start, End: v})
			i = v - 1
		}
	}
	scan(pathStart, queryStart, ";")
	scan(queryStart, end, "?&")
	return out
}

func isBase64URL(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// RemoveFromURI removes a path-style or form-style token from the request target Find scanned, by section
// 4.6.10's rule: if a sub-delimiter ends the token, everything from the parameter name through that sub-delimiter
// goes; otherwise everything from the reserved character before the name through the token goes. Other tokens
// are returned unchanged.
func RemoveFromURI(target string, t Located) string {
	if t.Where != InPath && t.Where != InQuery || t.Start < 1 || t.End > len(target) || t.Start > t.End {
		return target
	}
	if t.End < len(target) && strings.IndexByte("!$&'()*+,;=", target[t.End]) >= 0 {
		return target[:t.Start] + target[t.End+1:]
	}
	return target[:t.Start-1] + target[t.End:]
}
