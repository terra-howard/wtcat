package cat

import (
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Location is where a client was found to be, for catgeoiso3166 (decision 0021).
type Location struct {
	Country string // ISO 3166-1 alpha-2 code, such as "CA"; empty if the client could not be located
	Region  string // the ISO 3166-2 subdivision code after the dash, such as "ON"; empty if unknown
}

// ErrLocation means the client is not in a place the token's catgeoiso3166 claim lists, or could not be located.
var ErrLocation = fmt.Errorf("%w: the client is not in a place catgeoiso3166 lists", ErrUnacceptable)

// claimCatgeoiso3166 is the catgeoiso3166 claim key (section 4.6.14).
const claimCatgeoiso3166 = 316

// decodeCountries decodes catgeoiso3166: at least one ISO 3166 country code, each optionally followed by a dash and
// a region code. Only the syntax is checked; this package holds no copy of ISO's lists (decision 0021).
func decodeCountries(value cbor.RawMessage) ([]string, error) {
	entries, err := textArray(value, claimCatgeoiso3166)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		country, region, hasRegion := strings.Cut(e, "-")
		if len(country) != 2 || !allOf(country, isUpper) || hasRegion && (len(region) < 1 || len(region) > 3 || !allOf(region, isUpperOrDigit)) {
			return nil, malformed("claim 316 (catgeoiso3166) entry %q is not an ISO 3166 code", e)
		}
	}
	return entries, nil
}

func isUpper(c byte) bool { return 'A' <= c && c <= 'Z' }

func isUpperOrDigit(c byte) bool { return isUpper(c) || '0' <= c && c <= '9' }

func allOf(s string, f func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !f(s[i]) {
			return false
		}
	}
	return true
}

// checkLocation enforces catgeoiso3166 when the caller supplies a Location; without one the claim is ignored.
func checkLocation(c *Claims, req *Request) error {
	if c.countries == nil || req == nil || req.Location == nil {
		return nil
	}
	country, region := strings.ToUpper(req.Location.Country), strings.ToUpper(req.Location.Region)
	if country == "" {
		return fmt.Errorf("%w: the client could not be located", ErrLocation)
	}
	for _, e := range c.countries {
		listed, listedRegion, hasRegion := strings.Cut(e, "-")
		if listed == country && (!hasRegion || listedRegion == region) {
			return nil
		}
	}
	return ErrLocation
}
