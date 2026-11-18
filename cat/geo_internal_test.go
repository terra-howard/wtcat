package cat

import (
	"math"
	"strings"
	"testing"
)

// Published geohash values from outside CTA (decision 0027). Both come from the Geohash article on Wikipedia
// (https://en.wikipedia.org/wiki/Geohash, CC BY-SA 4.0), which CTA-5009-A itself names as the algorithm's
// established description: "ezs42" for 42.6, -5.6, and geohash.org's example "u4pruydqqvj" for 57.64911, 10.40744.
func TestEncodeGeohashPublishedValues(t *testing.T) {
	for _, tc := range []struct {
		lat, lon float64
		want     string
	}{
		{42.6, -5.6, "ezs42"},
		{57.64911, 10.40744, "u4pruydqqvj"},
	} {
		if got := encodeGeohash(tc.lat, tc.lon, len(tc.want)); got != tc.want {
			t.Errorf("encodeGeohash(%v, %v, %d) = %q, want %q", tc.lat, tc.lon, len(tc.want), got, tc.want)
		}
	}
}

// cell decodes a geohash into the bounds of its region, independently of encodeGeohash: each character's five
// bits halve longitude and latitude in turn, longitude first.
func cell(t *testing.T, g string) (latMin, latMax, lonMin, lonMax float64) {
	t.Helper()
	latMin, latMax, lonMin, lonMax = -90, 90, -180, 180
	even := true
	for _, ch := range g {
		v := strings.IndexRune("0123456789bcdefghjkmnpqrstuvwxyz", ch)
		if v < 0 {
			t.Fatalf("bad geohash %q", g)
		}
		for bit := 4; bit >= 0; bit-- {
			on := v>>bit&1 == 1
			if even {
				if mid := (lonMin + lonMax) / 2; on {
					lonMin = mid
				} else {
					lonMax = mid
				}
			} else {
				if mid := (latMin + latMax) / 2; on {
					latMin = mid
				} else {
					latMax = mid
				}
			}
			even = !even
		}
	}
	return
}

// TestEncodeGeohashProperties checks, over a grid of points, that each point lies in the cell its geohash names,
// and that every prefix of a geohash is the geohash at that shorter length.
func TestEncodeGeohashProperties(t *testing.T) {
	for lat := -89.75; lat < 90; lat += 7.3 {
		for lon := -179.9; lon < 180; lon += 11.7 {
			g := encodeGeohash(lat, lon, 9)
			for n := 1; n <= 9; n++ {
				if got := encodeGeohash(lat, lon, n); got != g[:n] {
					t.Fatalf("(%v, %v): length %d gives %q, not the prefix %q", lat, lon, n, got, g[:n])
				}
				a, b, c, d := cell(t, g[:n])
				if lat < a || lat >= b || lon < c || lon >= d {
					t.Fatalf("(%v, %v) is outside the cell of %q: [%v, %v) x [%v, %v)", lat, lon, g[:n], a, b, c, d)
				}
			}
		}
	}
}

func TestEncodeGeohashEdges(t *testing.T) {
	if got := encodeGeohash(-90, -180, 4); got != "0000" {
		t.Errorf("south-west corner: %q", got)
	}
	if got := encodeGeohash(math.Nextafter(90, 0), math.Nextafter(180, 0), 4); got != "zzzz" {
		t.Errorf("north-east corner: %q", got)
	}
	if got := encodeGeohash(0, 0, 1); got != "s" {
		t.Errorf("origin: %q", got)
	}
}

// TestDistance checks the haversine distance against two things outside it: the arc of one degree on the equator,
// which is the sphere's radius times pi/180, and the spherical law of cosines, an independent formula for the same
// great-circle distance.
func TestDistance(t *testing.T) {
	if got, want := distance(0, 0, 0, 1), earthRadius*math.Pi/180; math.Abs(got-want) > 1e-6 {
		t.Fatalf("one degree on the equator: %v, want %v", got, want)
	}
	if got, want := distance(0, 0, 1, 0), earthRadius*math.Pi/180; math.Abs(got-want) > 1e-6 {
		t.Fatalf("one degree of latitude: %v, want %v", got, want)
	}
	cosines := func(lat1, lon1, lat2, lon2 float64) float64 {
		r := math.Pi / 180
		c := math.Sin(lat1*r)*math.Sin(lat2*r) + math.Cos(lat1*r)*math.Cos(lat2*r)*math.Cos((lon2-lon1)*r)
		return earthRadius * math.Acos(math.Max(-1, math.Min(1, c)))
	}
	for _, p := range [][4]float64{
		{48.8566, 2.3522, 51.5074, -0.1278},
		{-33.8688, 151.2093, 35.6762, 139.6503},
		{40.7128, -74.0060, -22.9068, -43.1729},
		{10, 20, 30, 40},
		{-45, 170, 45, -170},
	} {
		got, want := distance(p[0], p[1], p[2], p[3]), cosines(p[0], p[1], p[2], p[3])
		if math.Abs(got-want) > 1e-6*want {
			t.Errorf("distance(%v) = %v, law of cosines gives %v", p, got, want)
		}
		if back := distance(p[2], p[3], p[0], p[1]); math.Abs(back-got) > 1e-9*got {
			t.Errorf("distance(%v) is not symmetric: %v and %v", p, got, back)
		}
	}
}
