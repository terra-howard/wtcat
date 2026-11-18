# 0019. The HTTP integration package

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation; pending her review. She may reverse it.
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

## Question asked

Decision 0018 put the HTTP integration package before phase 3. What shape would an expert give it?

## Reasoning

- **Keep `cat` free of `net/http` beyond its `Request` struct, and put HTTP behaviour in its own package,**
  `cathttp`. A recipient behind an edge runtime can still use `cat` alone.
- **Two layers, so each can be tested on its own and used alone:** pure functions that find tokens in a request
  and remove one from a URI, and an `Authorizer` that runs them through a `cat.Validator` and wraps an
  `http.Handler`.
- **Follow section 4.4's order and exclusivity exactly,** because it decides which token a request is judged by:
  if the `CTA-Common-Access-Token` field is present, nothing else is read; otherwise tokens are taken left to right
  from the URI, then from the Cookie field, and any acceptable one grants access.
- **Fail closed at every ambiguity:** a malformed field means no token, never a fallback to other locations; a DPoP
  authorization scheme, which phase 3 has not built, yields a token judged unsupported, never one accepted
  without its proof.

## Decision

1. **Package `cathttp`.** `Find(r *http.Request, opts) []Located` returns the tokens in order, each with where it
   was found and, for URI tokens, its position. `RemoveFromURI(uri string, t Located) string` applies section
   4.6.10's removal rule. `Authorizer` holds a `*cat.Validator` and the options, with `Authorize(r) (*cat.Token,
   error)` and `Middleware(next http.Handler) http.Handler`.
2. **Locations and names:** the field (default `CTA-Common-Access-Token`), path-style `;CAT=` and form-style
   `?CAT=` or `&CAT=` parameters (RFC 6570 Sections 3.2.7 to 3.2.9), a cookie (default `CAT`), and, only when
   configured, the `Bearer` authorization scheme. The parameter and cookie names are options, defaulting to `CAT`
   as section 4.4 suggests.
3. **The field** is parsed as a Structured Field item (RFC 9651): a token or a string, with parameters ignored. A
   field that is not a single valid item, or that appears with a value list, yields no usable token, and other
   locations are still not read.
4. **Order and number:** URI tokens left to right, then cookies left to right, then the authorization field. At
   least six are processed (section 4.4); the limit is an option, default 16, refused below 6. The first acceptable
   token wins. If none is, the error returned is that of the first valid but unacceptable token, so that `catif`
   (phase 4) can act on it, or else the first token's error.
5. **The request each token is judged with:** the absolute URI rebuilt from the request (scheme from TLS or an
   option, host, and the raw request URI), with that token removed by section 4.6.10's rule; the method; the
   header; the client address from `RemoteAddr` unless an option supplies a function (for proxies); an optional
   ASN lookup.
6. **The middleware** answers 401 when no token is acceptable, adds `private` to `Cache-Control` on every response
   to a request in which it processed a token (section 4.3.1.5.1), and removes the field, the token cookie and a
   token-bearing authorization field from the request it forwards. It leaves URI tokens in place, as section
   4.3.1.5.1 allows when removal is not practical, since rewriting the forwarded path changes what upstream sees.
   It is for content that requires a CAT; section 4.3.1.4 forbids denying access by CAT where none is required.

## Consequences

- `catif` handling (phase 4) will hook into the "first valid but unacceptable token" already returned.
- The DPoP scheme becomes usable in phase 3.
