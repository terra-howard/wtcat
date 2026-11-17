package cat

import (
	"fmt"
	"math"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Location is where a client was found to be, for catgeoiso3166 (decision 0021) and geohash (decision 0027).
type Location struct {
	Country string // ISO 3166-1 alpha-2 code, such as "CA"; empty if the client could not be located
	Region  string // the ISO 3166-2 subdivision code after the dash, such as "ON"; empty if unknown
	// Coordinates is the client's position in WGS84, for geohash. Nil means the recipient does not locate clients
	// by coordinates, and the claim is ignored. A geolocation database's point estimate can fall in a neighbouring
	// cell near a border; this package does not guess at accuracy.
	Coordinates *Coordinates
}

// Coordinates is a position in WGS84 degrees. Latitude must be in [-90, 90) and Longitude in [-180, 180), as
// CTA-5009-A requires of encoded points; any other value, or one that is not finite, is a failed lookup.
type Coordinates struct {
	Latitude  float64
	Longitude float64
}

// ErrLocation means the client is not in a place the token's catgeoiso3166 or geohash claim lists, or could not be
// located.
var ErrLocation = fmt.Errorf("%w: the client is not in a place the token's location claims list", ErrUnacceptable)

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

// geohashAlphabet is the geohash base-32 alphabet: digits and lower-case letters without a, i, l and o.
const geohashAlphabet = "0123456789bcdefghjkmnpqrstuvwxyz"

// maxPlainGeohash is the longest geohash an unencrypted claim may carry (CTA-5007-B section 4.6.16). This package
// does not decrypt, so it is the longest geohash it can accept (decision 0027).
const maxPlainGeohash = 4

// decodeGeohashes decodes geohash (282): an untagged text string, or an untagged array of untagged text strings,
// each 1 to 4 characters from the geohash alphabet in either case. It returns them in lower case. An empty array
// is allowed by the CDDL and names no region. Tags, including the CRS Wrapper (279), are refused earlier for the
// whole value; inside an array, textClaim refuses them because a tagged item is not a text string.
func decodeGeohashes(value cbor.RawMessage) ([]string, error) {
	var entries []string
	switch majorType(value) {
	case majorText:
		s, err := textClaim(value, claimGeohash)
		if err != nil {
			return nil, err
		}
		entries = []string{*s}
	case majorArray:
		var items []cbor.RawMessage
		if err := decMode.Unmarshal(value, &items); err != nil {
			return nil, err
		}
		entries = make([]string, 0, len(items))
		for _, item := range items {
			s, err := textClaim(item, claimGeohash)
			if err != nil {
				return nil, err
			}
			entries = append(entries, *s)
		}
	default:
		return nil, malformed("claim 282 (geohash) is not a text string or an array")
	}
	for i, e := range entries {
		if len(e) > maxPlainGeohash {
			return nil, malformed("claim 282 (geohash) entry %q is longer than %d characters, so it must be encrypted (section 4.6.16)", e, maxPlainGeohash)
		}
		lower := strings.ToLower(e)
		if lower == "" || !allOf(lower, func(c byte) bool { return strings.IndexByte(geohashAlphabet, c) >= 0 }) {
			return nil, malformed("claim 282 (geohash) entry %q is not a geohash", e)
		}
		entries[i] = lower
	}
	return entries, nil
}

// encodeGeohash encodes a point as a geohash of n characters: each character carries five bits, and the bits halve
// longitude and latitude in turn, longitude first, taking the upper half for a 1.
func encodeGeohash(lat, lon float64, n int) string {
	latMin, latMax, lonMin, lonMax := -90.0, 90.0, -180.0, 180.0
	out := make([]byte, n)
	even := true
	for i := range n {
		v := 0
		for range 5 {
			v <<= 1
			if even {
				if mid := (lonMin + lonMax) / 2; lon >= mid {
					v |= 1
					lonMin = mid
				} else {
					lonMax = mid
				}
			} else {
				if mid := (latMin + latMax) / 2; lat >= mid {
					v |= 1
					latMin = mid
				} else {
					latMax = mid
				}
			}
			even = !even
		}
		out[i] = geohashAlphabet[v]
	}
	return string(out)
}

// checkGeohash enforces geohash when the caller supplies coordinates; without them the claim is ignored. A point
// lies in a region when, encoded at the region's length, it gives the same geohash (CTA-5009-A section 8.4).
func checkGeohash(c *Claims, req *Request) error {
	if c.geohashes == nil || req == nil || req.Location == nil || req.Location.Coordinates == nil {
		return nil
	}
	lat, lon := req.Location.Coordinates.Latitude, req.Location.Coordinates.Longitude
	if math.IsNaN(lat) || math.IsNaN(lon) || lat < -90 || lat >= 90 || lon < -180 || lon >= 180 {
		return fmt.Errorf("%w: the client's coordinates are not a position", ErrLocation)
	}
	for _, g := range c.geohashes {
		if encodeGeohash(lat, lon, len(g)) == g {
			return nil
		}
	}
	return fmt.Errorf("%w: the client is in none of the geohash regions", ErrLocation)
}
