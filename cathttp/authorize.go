package cathttp

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

// ErrNoToken means the request carries no token in any place this Authorizer reads.
var ErrNoToken = errors.New("cathttp: no token in the request")

// Token limits (section 4.4).
const (
	MinTokens     = 6  // section 4.4 requires processing at least six tokens
	DefaultTokens = 16 // processed when MaxTokens is 0
)

// Authorizer judges requests by the CATs they carry (decision 0019).
type Authorizer struct {
	Validator *cat.Validator // required
	Options   Options        // where tokens are looked for
	MaxTokens int            // tokens judged per request; 0 means DefaultTokens, else at least MinTokens
	// Scheme is the request's scheme when it cannot be read from the request itself: "https" if the request
	// arrived over TLS, else this, else "http". Set it behind a proxy that terminates TLS.
	Scheme string
	// ClientIP returns the client's address; by default, the host part of the request's RemoteAddr. Set it behind
	// a proxy.
	ClientIP func(*http.Request) netip.Addr
	// ClientASN returns the client's autonomous system number, or 0 if unknown. Optional.
	ClientASN func(netip.Addr) uint32
}

// Authorize returns the first acceptable token in the request. If none is acceptable, the error is that of the
// first valid but unacceptable token, or else of the first token, so that its kind can be tested with errors.Is.
func (a *Authorizer) Authorize(r *http.Request) (*cat.Token, error) {
	limit, err := a.limit()
	if err != nil {
		return nil, err
	}
	tokens, err := Find(r, a.Options)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, ErrNoToken
	}
	if len(tokens) > limit {
		tokens = tokens[:limit] // section 4.4 lets a recipient treat the rest as absent
	}
	target := Target(r)
	ip := a.clientIP(r)
	var asn uint32
	if a.ClientASN != nil && ip.IsValid() {
		asn = a.ClientASN(ip)
	}
	var firstErr, firstUnacceptable error
	for _, t := range tokens {
		var tok *cat.Token
		if t.Where == InDPoP {
			err = fmt.Errorf("%w: a token in the DPoP authorization scheme needs a DPoP proof, which this version cannot verify", cwt.ErrUnsupported)
		} else {
			req := &cat.Request{Method: r.Method, URI: a.absolute(r, RemoveFromURI(target, t)), Header: r.Header, ClientIP: ip, ClientASN: asn}
			if tok, err = a.Validator.ValidateRequest(t.Text, req); err == nil {
				return tok, nil
			}
		}
		if firstErr == nil {
			firstErr = err
		}
		if firstUnacceptable == nil && errors.Is(err, cat.ErrUnacceptable) {
			firstUnacceptable = err
		}
	}
	if firstUnacceptable != nil {
		return nil, firstUnacceptable
	}
	return nil, firstErr
}

func (a *Authorizer) limit() (int, error) {
	switch {
	case a.Validator == nil:
		return 0, errors.New("cathttp: Authorizer has no Validator")
	case a.MaxTokens == 0:
		return DefaultTokens, nil
	case a.MaxTokens < MinTokens:
		return 0, fmt.Errorf("cathttp: MaxTokens %d is below the %d tokens CTA-5007-B requires recipients to process", a.MaxTokens, MinTokens)
	}
	return a.MaxTokens, nil
}

// absolute makes the request target absolute, for catu.
func (a *Authorizer) absolute(r *http.Request, target string) string {
	if !strings.HasPrefix(target, "/") {
		return target // already in absolute form
	}
	scheme := "http"
	switch {
	case r.TLS != nil:
		scheme = "https"
	case a.Scheme != "":
		scheme = a.Scheme
	}
	return scheme + "://" + r.Host + target
}

func (a *Authorizer) clientIP(r *http.Request) netip.Addr {
	if a.ClientIP != nil {
		return a.ClientIP(r)
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr()
	}
	ip, _ := netip.ParseAddr(r.RemoteAddr)
	return ip
}

// Middleware passes requests with an acceptable token to next, and answers others with 401. Whenever it has
// processed a token, it adds the private directive to the response's Cache-Control (section 4.3.1.5.1). It removes
// the token field, the token cookie and a token-bearing authorization field from the request it forwards; tokens in
// the URI stay, since rewriting the forwarded path changes what upstream sees. It panics if the Authorizer is
// misconfigured. Use it only for content that requires a CAT (section 4.3.1.4).
func (a *Authorizer) Middleware(next http.Handler) http.Handler {
	if _, err := a.limit(); err != nil {
		panic(err)
	}
	opts := a.Options.withDefaults()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := a.Authorize(r)
		if !errors.Is(err, ErrNoToken) {
			w = &privateWriter{ResponseWriter: w}
		}
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		forwarded := r.Clone(r.Context())
		forwarded.Header.Del(opts.Field)
		removeCookie(forwarded, opts.Cookie)
		if scheme, _, _ := strings.Cut(forwarded.Header.Get("Authorization"), " "); strings.EqualFold(scheme, "DPoP") ||
			strings.EqualFold(scheme, "Bearer") && opts.Bearer {
			forwarded.Header.Del("Authorization")
		}
		next.ServeHTTP(w, forwarded)
	})
}

// removeCookie removes every cookie of the given name from the request's Cookie field, keeping the others.
func removeCookie(r *http.Request, name string) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != name {
			r.AddCookie(c)
		}
	}
}

// privateWriter makes sure the response's Cache-Control carries the private directive, whatever the handler set,
// dropping a conflicting public directive.
type privateWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (p *privateWriter) WriteHeader(code int) {
	if !p.wroteHeader {
		p.wroteHeader = true
		ensurePrivate(p.Header())
	}
	p.ResponseWriter.WriteHeader(code)
}

func (p *privateWriter) Write(b []byte) (int, error) {
	if !p.wroteHeader {
		p.WriteHeader(http.StatusOK)
	}
	return p.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (p *privateWriter) Unwrap() http.ResponseWriter { return p.ResponseWriter }

func ensurePrivate(h http.Header) {
	var kept []string
	for _, v := range h.Values("Cache-Control") {
		for _, d := range strings.Split(v, ",") {
			d = strings.TrimSpace(d)
			name, _, _ := strings.Cut(d, "=")
			switch {
			case d == "", strings.EqualFold(name, "public"):
			case strings.EqualFold(name, "private"):
				return // already private
			default:
				kept = append(kept, d)
			}
		}
	}
	h.Set("Cache-Control", strings.Join(append(kept, "private"), ", "))
}
