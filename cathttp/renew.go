package cathttp

import (
	"net/http"
	"strings"

	"github.com/terra-howard/wtcat/cat"
)

// planRenewal works out how a renewal under the token's catr reaches the client (section 4.9.2, decision 0022): a
// redirect, as a location and status, or a function that adds a cookie or a header field to the response unless
// the handler has set one of that name. It returns neither when there is nothing to renew, or when the renewal
// cannot be conveyed safely.
func (a *Authorizer) planRenewal(r *http.Request, tok *cat.Token, loc Located, opts Options) (location string, status int, add func(http.Header)) {
	if a.Validator.Issuance == nil {
		return "", 0, nil
	}
	ren, err := a.Validator.Renew(tok, a.now())
	if err != nil || ren == nil {
		return "", 0, nil
	}
	typ := ren.Type
	headerName := ren.HeaderName
	if typ == cat.RenewAutomatic { // by the way the token came (section 4.9.2.1)
		switch loc.Where {
		case InCookie:
			typ = cat.RenewCookie
		case InField:
			typ = cat.RenewHeader
			if headerName == "" {
				headerName = opts.Field
			}
		case InAuthorization, InDPoP:
			typ = cat.RenewHeader
		case InPath, InQuery:
			typ = cat.RenewRedirect
		}
	}
	switch typ {
	case cat.RenewCookie:
		name := ren.CookieName
		if name == "" {
			name = opts.Cookie
		}
		if !isToken(name) {
			return "", 0, nil
		}
		for _, p := range ren.CookieParams {
			if strings.IndexFunc(p, func(c rune) bool { return c < 0x20 || c == 0x7f || c == ';' }) >= 0 {
				return "", 0, nil // RFC 6265 Section 5.2: a parameter cannot hold a control character or ";"
			}
		}
		value := strings.Join(append([]string{name + "=" + ren.Token}, ren.CookieParams...), "; ")
		return "", 0, func(h http.Header) {
			for _, c := range h.Values("Set-Cookie") {
				if existing, _, _ := strings.Cut(c, "="); strings.TrimSpace(existing) == name {
					return // the handler set this cookie itself
				}
			}
			h.Add("Set-Cookie", value)
		}
	case cat.RenewHeader:
		if headerName == "" {
			headerName = DefaultField
		}
		if !isToken(headerName) {
			return "", 0, nil
		}
		item := []string{`"` + ren.Token + `"`}
		for _, p := range ren.HeaderParams {
			if rest, ok := skipParameter(p); !ok || rest != "" {
				return "", 0, nil // not an RFC 9651 parameter
			}
			item = append(item, p)
		}
		value := strings.Join(item, ";")
		return "", 0, func(h http.Header) {
			if len(h.Values(headerName)) == 0 {
				h.Set(headerName, value)
			}
		}
	case cat.RenewRedirect:
		if loc.Where != InPath && loc.Where != InQuery {
			return "", 0, nil // section 4.9.2.4: only for a token found in the URI
		}
		target := Target(r)
		valueStart := loc.Start + len(opts.Param) + 1
		if valueStart > loc.End || loc.End > len(target) {
			return "", 0, nil
		}
		status = ren.Status
		if status == 0 {
			status = http.StatusTemporaryRedirect
		}
		return a.absolute(r, target[:valueStart]+ren.Token+target[loc.End:]), status, nil
	}
	return "", 0, nil
}

func isToken(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isTchar(s[i]) {
			return false
		}
	}
	return s != ""
}
