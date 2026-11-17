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

// maxPlainGeohash is the longest geohash an unencrypted claim may carry (CTA-5007-B section 4.6.16; decision 0027),
// and maxGeohash the longest this package reads from an encrypted one: twelve characters is a cell a few
// centimetres across (decision 0030).
const (
	maxPlainGeohash = 4
	maxGeohash      = 12
)

// decodeGeohashes decodes geohash (282): an untagged text string, or an untagged array of untagged text strings,
// each 1 to 4 characters from the geohash alphabet in either case. It returns them in lower case. An empty array
// is allowed by the CDDL and names no region. Tags, including the CRS Wrapper (279), are refused earlier for the
// whole value; inside an array, textClaim refuses them because a tagged item is not a text string.
func decodeGeohashes(value cbor.RawMessage, encrypted bool) ([]string, error) {
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
		if len(e) > maxPlainGeohash && !encrypted {
			return nil, malformed("claim 282 (geohash) entry %q is longer than %d characters, so it must be encrypted (section 4.6.16)", e, maxPlainGeohash)
		}
		if len(e) > maxGeohash {
			return nil, malformed("claim 282 (geohash) entry %q is longer than %d characters", e, maxGeohash)
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

// coordinatesOK reports whether a Location's coordinates are a position: latitude in [-90, 90) and longitude in
// [-180, 180). NaN needs no test of its own, since every comparison with it is false.
func coordinatesOK(c *Coordinates) bool {
	return c.Latitude >= -90 && c.Latitude < 90 && c.Longitude >= -180 && c.Longitude < 180
}

// checkGeohash enforces geohash when the caller supplies coordinates; without them the claim is ignored. A point
// lies in a region when, encoded at the region's length, it gives the same geohash (CTA-5009-A section 8.4).
func checkGeohash(c *Claims, req *Request) error {
	if c.geohashes == nil || req == nil || req.Location == nil || req.Location.Coordinates == nil {
		return nil
	}
	lat, lon := req.Location.Coordinates.Latitude, req.Location.Coordinates.Longitude
	if !coordinatesOK(req.Location.Coordinates) {
		return fmt.Errorf("%w: the client's coordinates are not a position", ErrLocation)
	}
	for _, g := range c.geohashes {
		if encodeGeohash(lat, lon, len(g)) == g {
			return nil
		}
	}
	return fmt.Errorf("%w: the client is in none of the geohash regions", ErrLocation)
}

// geocoord is one catgeocoord location: a centre in WGS84 degrees and a radius in metres.
type geocoord struct{ lat, lon, radius float64 }

// earthRadius is the mean radius of the Earth in metres (IUGG). Distances on a sphere of this radius are within
// about 0.5% of distances on the WGS84 ellipsoid (decision 0030).
const earthRadius = 6371008.8

// decodeGeocoords decodes catgeocoord (317): an untagged array of at least one untagged [latitude, longitude,
// radius] array, latitude and longitude as numbers in range and radius as an unsigned integer of metres. It is
// valid only in an encrypted claim set (section 4.6.15).
func decodeGeocoords(value cbor.RawMessage, encrypted bool) ([]geocoord, error) {
	if !encrypted {
		return nil, malformed("claim 317 (catgeocoord) must be conveyed encrypted (section 4.6.15)")
	}
	if majorType(value) != majorArray {
		return nil, malformed("claim 317 (catgeocoord) is not an array")
	}
	var items []cbor.RawMessage
	if err := decMode.Unmarshal(value, &items); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, malformed("claim 317 (catgeocoord) is an empty array")
	}
	out := make([]geocoord, 0, len(items))
	for _, item := range items {
		var parts []cbor.RawMessage
		if majorType(item) != majorArray || decMode.Unmarshal(item, &parts) != nil || len(parts) != 3 {
			return nil, malformed("claim 317 (catgeocoord) has a location that is not [latitude, longitude, radius]")
		}
		var g geocoord
		for i, dst := range []*float64{&g.lat, &g.lon} {
			f, err := decodeNumber(parts[i])
			if err != nil {
				return nil, malformed("claim 317 (catgeocoord): %v", err)
			}
			*dst = f
		}
		if majorType(parts[2]) != majorUnsigned {
			return nil, malformed("claim 317 (catgeocoord) has a radius that is not an unsigned integer")
		}
		var r uint64
		if err := decMode.Unmarshal(parts[2], &r); err != nil {
			return nil, err
		}
		g.radius = float64(r)
		if g.lat < -90 || g.lat > 90 || g.lon < -180 || g.lon > 180 {
			return nil, malformed("claim 317 (catgeocoord) has a centre that is not a position")
		}
		out = append(out, g)
	}
	return out, nil
}

// decodeNumber decodes an untagged CBOR integer or floating-point number.
func decodeNumber(raw cbor.RawMessage) (float64, error) {
	switch majorType(raw) {
	case majorUnsigned, majorNegative:
		var i int64
		if err := decMode.Unmarshal(raw, &i); err != nil {
			return 0, err
		}
		return float64(i), nil
	case majorSimple:
		var f float64
		if err := decMode.Unmarshal(raw, &f); err != nil {
			return 0, fmt.Errorf("not a number")
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, fmt.Errorf("not a finite number")
		}
		return f, nil
	}
	return 0, fmt.Errorf("not a number")
}

// distance is the great-circle distance in metres between two points, by the haversine formula.
func distance(lat1, lon1, lat2, lon2 float64) float64 {
	rad := math.Pi / 180
	dLat, dLon := (lat2-lat1)*rad, (lon2-lon1)*rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthRadius * math.Asin(math.Min(1, math.Sqrt(a)))
}

// checkGeocoord enforces catgeocoord when the caller supplies coordinates; without them the claim is ignored. A
// client is accepted when it is within the radius of at least one location.
func checkGeocoord(c *Claims, req *Request) error {
	if c.geocoords == nil || req == nil || req.Location == nil || req.Location.Coordinates == nil {
		return nil
	}
	p := req.Location.Coordinates
	if !coordinatesOK(p) {
		return fmt.Errorf("%w: the client's coordinates are not a position", ErrLocation)
	}
	for _, g := range c.geocoords {
		if distance(g.lat, g.lon, p.Latitude, p.Longitude) <= g.radius {
			return nil
		}
	}
	return fmt.Errorf("%w: the client is outside every catgeocoord location", ErrLocation)
}
