package cat

import (
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/terra-howard/wtcat/cwt"
)

// ErrMethod means the request's method is not one the token's catm claim lists.
var ErrMethod = fmt.Errorf("%w: catm does not list the request's method", ErrUnacceptable)

// ErrURI means the request URI does not satisfy the token's catu claim, or cannot be parsed to check it.
var ErrURI = fmt.Errorf("%w: the request URI does not satisfy catu", ErrUnacceptable)

// ErrNetwork means neither the client's address nor its ASN is listed in the token's catnip claim.
var ErrNetwork = fmt.Errorf("%w: the client's network is not listed in catnip", ErrUnacceptable)

// ErrHeader means a request header does not satisfy the token's cath claim.
var ErrHeader = fmt.Errorf("%w: a request header does not satisfy cath", ErrUnacceptable)

// Request describes what the request claims compare a token with (decision 0017).
type Request struct {
	Method    string      // compared case-sensitively (catm)
	URI       string      // the absolute request URI, with the token already removed (catu)
	Header    http.Header // request header fields (cath)
	ClientIP  netip.Addr  // the client's address (catnip)
	ClientASN uint32      // the client's autonomous system number, 0 if unknown (catnip)

	// ReceivedURI is the absolute request URI as received, before the token was removed, for the htu of a DPoP
	// proof (decision 0020). When empty, URI is used.
	ReceivedURI string
	// ViaDPoPScheme reports that the token arrived in Authorization: DPoP, so it must be bound by cnf and the
	// proof must carry ath (RFC 9449 Section 7).
	ViaDPoPScheme bool
	// MOQT is the MOQT action the token is presented for, which the moqt claim must authorize (decision 0035). Nil
	// means an HTTP request, which the moqt claim does not judge.
	MOQT *MOQTAction
	// Location is where the client was found to be, for catgeoiso3166. Nil means the recipient does not locate
	// clients, and the claim is ignored (decision 0021).
	Location *Location
	// Connection describes the connection the request came over, for catalpn and cattpk. Nil means the recipient
	// does not supply it, and those claims are ignored (decision 0021).
	Connection *Connection
}

// ValidateRequest is Validate for a token presented with a request, so that the token's request claims can be
// checked too. Validate refuses tokens that carry request claims, since it has nothing to check them against.
func (v *Validator) ValidateRequest(token string, req *Request) (*Token, error) {
	return v.validate(token, req)
}

// checkRequest checks catm, catnip, catu and cath, and refuses a token with any request claim when there is no
// request. cnf, which needs one too, is checked by checkConfirmation.
func checkRequest(c *Claims, req *Request) error {
	if c.Methods == nil && c.headers == nil && c.uri == nil && c.network == nil && c.jkt == nil && c.ckt == nil {
		return nil
	}
	if req == nil {
		return fmt.Errorf("%w: the token has request claims, which need ValidateRequest", cwt.ErrUnsupported)
	}
	if c.Methods != nil && !slices.Contains(c.Methods, req.Method) {
		return ErrMethod
	}
	if c.network != nil && !catnipMatches(c.network, req.ClientIP, req.ClientASN) {
		return ErrNetwork
	}
	if c.uri != nil {
		parts, err := normalizeURI(req.URI)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrURI, err)
		}
		for _, cm := range c.uri {
			if !cm.match.matches(parts.component(cm.component)) {
				return fmt.Errorf("%w: component %d", ErrURI, cm.component)
			}
		}
	}
	for _, h := range c.headers {
		value, present := headerValue(req.Header, h.name)
		if !present || !h.match.matches(value) {
			return fmt.Errorf("%w: %s", ErrHeader, h.name)
		}
	}
	return nil
}

// headerValue returns a header's field value, its field lines joined with ", " (RFC 9110 Section 5.2), finding the
// name case-insensitively. A header built in code can hold one field under names that differ in case; their lines
// are taken in the sorted order of the names, so that the result never depends on how the map is walked.
func headerValue(h http.Header, name string) (string, bool) {
	var names []string
	for k := range h {
		if strings.EqualFold(k, name) {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	var lines []string
	for _, k := range names {
		lines = append(lines, h[k]...)
	}
	return strings.Join(lines, ", "), len(names) > 0
}
