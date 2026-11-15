package cat

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/terra-howard/wtcat/cwt"
)

func TestNumericDateCompare(t *testing.T) {
	for _, tc := range []struct {
		name string
		date NumericDate
		at   time.Time
		want int
	}{
		{"integer date, a nanosecond before", NumericDate{sec: 1000}, time.Unix(999, 999999999), -1},
		{"integer date, exactly", NumericDate{sec: 1000}, time.Unix(1000, 0), 0},
		{"integer date, a nanosecond after", NumericDate{sec: 1000}, time.Unix(1000, 1), 1},
		{"fractional date, a whole second before", NumericDate{sec: 1000, frac: 0.5}, time.Unix(1000, 0), -1},
		{"fractional date, a nanosecond before", NumericDate{sec: 1000, frac: 0.5}, time.Unix(1000, 499999999), -1},
		{"fractional date, exactly", NumericDate{sec: 1000, frac: 0.5}, time.Unix(1000, 500000000), 0},
		{"fractional date, a nanosecond after", NumericDate{sec: 1000, frac: 0.5}, time.Unix(1000, 500000001), 1},
		{"fractional date, the next second", NumericDate{sec: 1000, frac: 0.5}, time.Unix(1001, 0), 1},
		{"negative fractional date, exactly", NumericDate{sec: -2, frac: 0.5}, time.Unix(-2, 500000000), 0},
		{"negative fractional date, a nanosecond before", NumericDate{sec: -2, frac: 0.5}, time.Unix(-2, 499999999), -1},
	} {
		if got := tc.date.compare(tc.at); got != tc.want {
			t.Errorf("%s: compare = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestNumericDateFromFloat(t *testing.T) {
	for _, tc := range []struct {
		in       float64
		wantSec  int64
		wantFrac float64
	}{
		{1700000000.5, 1700000000, 0.5},
		{-1.5, -2, 0.5},
		{0.25, 0, 0.25},
		{-0.25, -1, 0.75},
		{-(1 << 63), math.MinInt64, 0},
	} {
		d, err := dateFromFloat(tc.in)
		if err != nil {
			t.Errorf("dateFromFloat(%v): %v", tc.in, err)
			continue
		}
		if d.Unix() != tc.wantSec || d.Fraction() != tc.wantFrac {
			t.Errorf("dateFromFloat(%v) = (%d, %v), want (%d, %v)", tc.in, d.Unix(), d.Fraction(), tc.wantSec, tc.wantFrac)
		}
	}
}

func TestNumericDateFromFloatRefusesTheUnrepresentable(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want error
	}{
		{1 << 63, cwt.ErrUnsupported},
		{math.Nextafter(-(1 << 63), math.Inf(-1)), cwt.ErrUnsupported},
		{math.NaN(), cwt.ErrMalformed},
		{math.Inf(1), cwt.ErrMalformed},
		{math.Inf(-1), cwt.ErrMalformed},
	} {
		if _, err := dateFromFloat(tc.in); !errors.Is(err, tc.want) {
			t.Errorf("dateFromFloat(%v) = %v, want an error wrapping %v", tc.in, err, tc.want)
		}
	}
}

// A tiny negative date's fraction rounds to 1 in float64; it must stay below 1 and still compare correctly.
func TestNumericDateFromATinyNegativeFloat(t *testing.T) {
	d, err := dateFromFloat(-1e-300)
	if err != nil {
		t.Fatal(err)
	}
	if d.Unix() != -1 || !(d.Fraction() >= 0 && d.Fraction() < 1) {
		t.Fatalf("dateFromFloat(-1e-300) = (%d, %v), want -1 and a fraction in [0, 1)", d.Unix(), d.Fraction())
	}
	if got := d.compare(time.Unix(0, 0)); got != 1 {
		t.Errorf("compare(epoch) = %d, want 1: the epoch is after a date just below it", got)
	}
	if got := d.compare(time.Unix(-1, 999999999)); got != -1 {
		t.Errorf("compare(epoch minus 1 ns) = %d, want -1", got)
	}
}
