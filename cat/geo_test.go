package cat_test

import (
	"math"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

func located(country, region string) *cat.Request {
	req := get()
	req.Location = &cat.Location{Country: country, Region: region}
	return req
}

func TestCatgeoiso3166(t *testing.T) {
	token := claimsToken(t, map[any]any{316: []string{"CA-ON", "US"}})
	cases := []struct {
		name string
		req  *cat.Request
		want error
	}{
		{"a listed country", located("US", "TX"), nil},
		{"a listed region", located("CA", "ON"), nil},
		{"a listed country, given in lowercase", located("us", ""), nil},
		{"an unlisted region of a country listed by region", located("CA", "QC"), cat.ErrLocation},
		{"an unlisted country", located("FR", ""), cat.ErrLocation},
		{"a client that could not be located", located("", ""), cat.ErrLocation},
		{"a recipient that does not locate clients", get(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validator().ValidateRequest(token, tc.req)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateRequest: %v", err)
				}
				return
			}
			wantKind(t, err, tc.want)
			wantKind(t, err, cat.ErrUnacceptable)
		})
	}
}

func TestCatgeoiso3166Syntax(t *testing.T) {
	for _, entry := range []string{"ca", "CAN", "C", "CA-", "CA-ABCD", "CA_ON", "CA-on"} {
		_, err := validator().ValidateRequest(claimsToken(t, map[any]any{316: []string{entry}}), located("CA", "ON"))
		wantKind(t, err, cwt.ErrMalformed)
	}
	for _, entry := range []string{"CA", "CA-ON", "GB-ENG", "FR-75"} {
		if _, err := validator().ValidateRequest(claimsToken(t, map[any]any{316: []string{entry}}), get()); err != nil {
			t.Errorf("%q: %v", entry, err)
		}
	}
}

func atPoint(lat, lon float64) *cat.Request {
	req := get()
	req.Location = &cat.Location{Coordinates: &cat.Coordinates{Latitude: lat, Longitude: lon}}
	return req
}

// TestGeohash checks claim 282 against a client's coordinates (decision 0027). "9vf" and "9vg" are cells over Texas;
// 32.4, -99.7 lies in "9vc0", and 48.86, 2.35 is Paris.
func TestGeohash(t *testing.T) {
	one := claimsToken(t, map[any]any{282: "9vc0"})
	upper := claimsToken(t, map[any]any{282: "9VC"})
	list := claimsToken(t, map[any]any{282: []string{"u09", "9vc0"}})
	empty := claimsToken(t, map[any]any{282: []string{}})
	nan := atPoint(math.NaN(), 0)
	cases := []struct {
		name  string
		token string
		req   *cat.Request
		want  error
	}{
		{"a client in the region", one, atPoint(32.4, -99.7), nil},
		{"a client outside the region", one, atPoint(48.86, 2.35), cat.ErrLocation},
		{"upper case in the claim", upper, atPoint(32.4, -99.7), nil},
		{"a client in one region of a list", list, atPoint(48.86, 2.35), nil},
		{"an empty list names no region", empty, atPoint(48.86, 2.35), cat.ErrLocation},
		{"coordinates that are not finite", one, nan, cat.ErrLocation},
		{"a latitude out of range", one, atPoint(90, 0), cat.ErrLocation},
		{"a longitude out of range", one, atPoint(0, 180), cat.ErrLocation},
		{"a recipient without coordinates", one, located("US", ""), nil},
		{"a recipient that does not locate clients", one, get(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validator().ValidateRequest(tc.token, tc.req)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateRequest: %v", err)
				}
				return
			}
			wantKind(t, err, tc.want)
			wantKind(t, err, cat.ErrUnacceptable)
		})
	}
}

func TestGeohashSyntax(t *testing.T) {
	for name, value := range map[string]any{
		"five characters, which must be encrypted": "9vc0d",
		"an empty string":                          "",
		"a letter outside the alphabet":            "9va",
		"punctuation":                              "9v-",
		"a number":                                 9,
		"a list holding a number":                  []any{"9vc", 9},
		"a list holding a long geohash":            []any{"u09", "u09tgf"},
		"a CRS Wrapper":                            cbor.Tag{Number: 279, Content: []any{4326, "9vc0"}},
		"a CRS Wrapper inside a list":              []any{cbor.Tag{Number: 279, Content: []any{4326, "9vc0"}}},
		"the geohash tag":                          cbor.Tag{Number: 301, Content: "9vc0"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validator().ValidateRequest(claimsToken(t, map[any]any{282: value}), atPoint(32.4, -99.7))
			wantKind(t, err, cwt.ErrMalformed)
		})
	}
}

// TestGeohashAbsent checks that coordinates alone refuse nothing: a token without geohash is not checked against
// them (decision 0027).
func TestGeohashAbsent(t *testing.T) {
	if _, err := validator().ValidateRequest(claimsToken(t, map[any]any{1: "issuer"}), atPoint(48.86, 2.35)); err != nil {
		t.Fatalf("ValidateRequest: %v", err)
	}
}

// TestGeohashCoordinateRange checks the range CTA-5009-A sets for encoded points, latitude in [-90, 90) and longitude
// in [-180, 180), at the corner cells "0000" and "zzzz". Each refused point would encode into the listed cell if it
// were not refused first, so these tests see the range check itself, not a mismatch.
func TestGeohashCoordinateRange(t *testing.T) {
	sw := claimsToken(t, map[any]any{282: "0000"})
	ne := claimsToken(t, map[any]any{282: "zzzz"})
	cases := []struct {
		name  string
		token string
		lat   float64
		lon   float64
		want  error
	}{
		{"the south-west corner itself", sw, -90, -180, nil},
		{"a latitude below -90", sw, -90.5, -179.9, cat.ErrLocation},
		{"a longitude below -180", sw, -89.9, -180.5, cat.ErrLocation},
		{"a latitude that is not a number", sw, math.NaN(), -179.9, cat.ErrLocation},
		{"a longitude that is not a number", sw, -89.9, math.NaN(), cat.ErrLocation},
		{"just inside the north-east corner", ne, math.Nextafter(90, 0), math.Nextafter(180, 0), nil},
		{"a latitude of 90", ne, 90, 179.9, cat.ErrLocation},
		{"a longitude of 180", ne, 89.9, 180, cat.ErrLocation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validator().ValidateRequest(tc.token, atPoint(tc.lat, tc.lon))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateRequest: %v", err)
				}
				return
			}
			wantKind(t, err, tc.want)
		})
	}
}
