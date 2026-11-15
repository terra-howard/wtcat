package cat

import (
	"fmt"
	"net/http"
	"net/netip"
	"slices"

	"github.com/terra-howard/wtcat/cwt"
)

// ErrMethod means the request's method is not one the token's catm claim lists.
var ErrMethod = fmt.Errorf("%w: catm does not list the request's method", ErrUnacceptable)

// Request describes what the request claims compare a token with (decision 0017).
type Request struct {
	Method    string      // compared case-sensitively (catm)
	URI       string      // the absolute request URI, with the token already removed (catu)
	Header    http.Header // request header fields (cath)
	ClientIP  netip.Addr  // the client's address (catnip)
	ClientASN uint32      // the client's autonomous system number, 0 if unknown (catnip)
}

// ValidateRequest is Validate for a token presented with a request, so that the token's request claims can be
// checked too. Validate refuses tokens that carry request claims, since it has nothing to check them against.
func (v *Validator) ValidateRequest(token string, req *Request) (*Token, error) {
	return v.validate(token, req)
}

// checkRequest checks the request claims phase 2 enforces so far.
func checkRequest(c *Claims, req *Request) error {
	if c.Methods == nil {
		return nil
	}
	if req == nil {
		return fmt.Errorf("%w: the token has request claims (catm), which need ValidateRequest", cwt.ErrUnsupported)
	}
	if !slices.Contains(c.Methods, req.Method) {
		return ErrMethod
	}
	return nil
}
