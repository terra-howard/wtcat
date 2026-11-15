package cat

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

// Unacceptable is the error for a valid token that one of its claims refuses (section 4.3.1.2). It unwraps to the
// specific error, such as ErrExpired, so errors.Is works as it does on that error (decision 0022).
type Unacceptable struct {
	Token *Token // the valid token
	Claim int64  // the key of the claim that refused it
	Err   error
}

func (u *Unacceptable) Error() string { return u.Err.Error() }

// Unwrap returns the specific error.
func (u *Unacceptable) Unwrap() error { return u.Err }

// IfResponse is the response a catif claim asks for (section 4.9.1).
type IfResponse struct {
	Status int
	Header http.Header
}

// keyedError marks an error with the claim that caused it, where the error alone does not say.
type keyedError struct {
	key int64
	err error
}

func (k *keyedError) Error() string { return k.err.Error() }
func (k *keyedError) Unwrap() error { return k.err }

// claimOfError maps each acceptance error to the claim it reports.
var claimOfError = []struct {
	err error
	key int64
}{
	{ErrIssuer, claimIss}, {ErrAudience, claimAud}, {ErrExpired, claimExp}, {ErrNotYetValid, claimNbf},
	{ErrMethod, claimCatm}, {ErrURI, claimCatu}, {ErrHeader, claimCath}, {ErrNetwork, claimCatnip},
	{ErrProof, claimCnf}, {ErrReplay, claimCatreplay}, {ErrLocation, claimCatgeoiso3166},
}

// refusingClaim reports which claim an acceptance error belongs to.
func refusingClaim(err error) (int64, bool) {
	var k *keyedError
	if errors.As(err, &k) {
		return k.key, true
	}
	for _, c := range claimOfError {
		if errors.Is(err, c.err) {
			return c.key, true
		}
	}
	return 0, false
}

// IfResponse returns the response the refused token's catif claim asks for: the action of the first member whose
// key is, or lists, the refusing claim (decision 0022). It returns nil if there is no such member, or if the claim
// cannot be followed safely; a catif never changes why a token was refused.
func (v *Validator) IfResponse(u *Unacceptable, req *Request, now time.Time) *IfResponse {
	if u == nil || u.Token == nil || u.Token.Claims.catif == nil {
		return nil
	}
	entries, ok := mapEntries(u.Token.Claims.catif)
	if !ok {
		return nil
	}
	for _, e := range entries {
		if labelMatches(e[0], u.Claim) {
			return v.ifAction(e[1], u.Claim, req, now)
		}
	}
	return nil
}

// mapEntries splits an encoded map into its raw keys and values, which may be arrays, as catif's keys can be.
func mapEntries(data []byte) ([][2]cbor.RawMessage, bool) {
	if len(data) == 0 || majorType(data) != majorMap {
		return nil, false
	}
	info := data[0] & 0x1f
	count, rest := uint64(info), data[1:]
	if info >= 24 && info <= 27 {
		n := 1 << (info - 24)
		if len(rest) < n {
			return nil, false
		}
		count, rest = readUint(rest[:n]), rest[n:]
	} else if info > 27 {
		return nil, false
	}
	if count > uint64(len(rest)) {
		return nil, false
	}
	out := make([][2]cbor.RawMessage, 0, count)
	for i := uint64(0); i < count; i++ {
		var key, value cbor.RawMessage
		var err error
		if rest, err = decMode.UnmarshalFirst(rest, &key); err != nil {
			return nil, false
		}
		if rest, err = decMode.UnmarshalFirst(rest, &value); err != nil {
			return nil, false
		}
		out = append(out, [2]cbor.RawMessage{key, value})
	}
	return out, len(rest) == 0
}

// labelMatches reports whether a catif key is the claim's label, or an array of labels holding it.
func labelMatches(key cbor.RawMessage, claim int64) bool {
	switch majorType(key) {
	case majorUnsigned, majorNegative:
		var label int64
		return decMode.Unmarshal(key, &label) == nil && label == claim
	case majorArray:
		var labels []any
		if decMode.Unmarshal(key, &labels) != nil {
			return false
		}
		for _, l := range labels {
			switch n := l.(type) {
			case uint64:
				if claim >= 0 && n == uint64(claim) {
					return true
				}
			case int64:
				if n == claim {
					return true
				}
			}
		}
	}
	return false
}

// ifAction builds the response from an action: [status, headers?, kid?].
func (v *Validator) ifAction(raw cbor.RawMessage, claim int64, req *Request, now time.Time) *IfResponse {
	var parts []cbor.RawMessage
	if majorType(raw) != majorArray || decMode.Unmarshal(raw, &parts) != nil || len(parts) < 1 || len(parts) > 3 {
		return nil
	}
	var status uint64
	if majorType(parts[0]) != majorUnsigned || decMode.Unmarshal(parts[0], &status) != nil || status < 100 || status > 599 {
		return nil
	}
	kid := ""
	if len(parts) == 3 {
		s, err := textClaim(parts[2], claimCatif)
		if err != nil {
			return nil
		}
		kid = *s
	}
	resp := &IfResponse{Status: int(status), Header: http.Header{}}
	if len(parts) < 2 {
		return resp
	}
	headers, ok := mapEntries(parts[1])
	if !ok {
		return nil
	}
	for _, h := range headers {
		name, err := textClaim(h[0], claimCatif)
		if err != nil || !isFieldName(*name) {
			return nil
		}
		value, ok := v.actionValue(h[1], kid, claim, req, now)
		if !ok || strings.IndexFunc(value, func(c rune) bool { return c < 0x20 && c != '\t' || c == 0x7f }) >= 0 {
			return nil // a value that could break the response's framing
		}
		resp.Header.Set(*name, value)
	}
	return resp
}

func isFieldName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return s != ""
}

// actionValue builds one header value of an action: a string as it is, or an array whose members are concatenated.
func (v *Validator) actionValue(raw cbor.RawMessage, kid string, claim int64, req *Request, now time.Time) (string, bool) {
	if majorType(raw) == majorText {
		s, err := textClaim(raw, claimCatif)
		return deref(s), err == nil
	}
	var items []cbor.RawMessage
	if majorType(raw) != majorArray || decMode.Unmarshal(raw, &items) != nil {
		return "", false
	}
	var b strings.Builder
	for _, item := range items {
		switch majorType(item) {
		case majorText:
			s, err := textClaim(item, claimCatif)
			if err != nil {
				return "", false
			}
			b.WriteString(*s)
		case majorUnsigned, majorNegative:
			b.WriteString(substitute(item, claim, req))
		case majorMap:
			b.WriteString(v.mint(item, kid, claim, req, now))
		default:
			return "", false
		}
	}
	return b.String(), true
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// substitute replaces an integer in a catif header value (section 4.9.1): 0 the requested URI, 1 the URI with the
// token removed, 2 the refusing claim's key as a CBOR list, all base64url; any other integer the empty string.
func substitute(item cbor.RawMessage, claim int64, req *Request) string {
	var n int64
	if decMode.Unmarshal(item, &n) != nil || req == nil {
		return ""
	}
	switch n {
	case 0:
		uri := req.ReceivedURI
		if uri == "" {
			uri = req.URI
		}
		return base64.RawURLEncoding.EncodeToString([]byte(uri))
	case 1:
		return base64.RawURLEncoding.EncodeToString([]byte(req.URI))
	case 2:
		keys, err := cbor.Marshal([]int64{claim})
		if err != nil {
			return ""
		}
		return base64.RawURLEncoding.EncodeToString(keys)
	}
	return ""
}

// mint turns a claim-set map into a CAT signed with the key kid names, filling null iss and iat and processing
// catifdata (section 4.9.1). Without Issuance, a kid or that key, it returns the empty string, which the section
// allows.
func (v *Validator) mint(item cbor.RawMessage, kid string, claim int64, req *Request, now time.Time) string {
	if v.Issuance == nil || v.Issuance.Key == nil || kid == "" {
		return ""
	}
	var claims map[any]cbor.RawMessage
	if decMode.Unmarshal(item, &claims) != nil {
		return ""
	}
	null := func(r cbor.RawMessage) bool { return len(r) == 1 && r[0] == cborNull }
	set := func(key uint64, value any) bool {
		b, err := issueEncoder.Marshal(value)
		claims[key] = b
		return err == nil
	}
	if null(claims[uint64(claimIss)]) && !set(claimIss, v.Issuance.Issuer) {
		return ""
	}
	if null(claims[uint64(claimIat)]) && !set(claimIat, now.Unix()) {
		return ""
	}
	if data, ok := claims[uint64(claimCatifdata)]; ok {
		processed, ok := catifdata(data, claim, req)
		if !ok || !set(claimCatifdata, processed) {
			return ""
		}
	}
	payload, err := issueEncoder.Marshal(claims)
	if err != nil {
		return ""
	}
	key, err := v.Issuance.Key(kid)
	if err != nil {
		return ""
	}
	raw, err := cwt.Issue(payload, key)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// catifdata processes a catifdata value inside a minted claim set: a string stays as it is; an array keeps its
// strings, substitutes its integers and turns its maps into empty strings, without concatenating.
func catifdata(raw cbor.RawMessage, claim int64, req *Request) (any, bool) {
	if majorType(raw) == majorText {
		s, err := textClaim(raw, claimCatifdata)
		return deref(s), err == nil
	}
	var items []cbor.RawMessage
	if majorType(raw) != majorArray || decMode.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		switch majorType(item) {
		case majorText:
			s, err := textClaim(item, claimCatifdata)
			if err != nil {
				return nil, false
			}
			out = append(out, *s)
		case majorUnsigned, majorNegative:
			out = append(out, substitute(item, claim, req))
		case majorMap:
			out = append(out, "")
		default:
			return nil, false
		}
	}
	return out, true
}
