package cwt_test

// These tests were in package cat until task 38, when cat's NumericDate became an alias of this one.

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/terra-howard/wtcat/cwt"
)

func floatDate(t *testing.T, f float64) *cwt.NumericDate {
	t.Helper()
	d, err := cwt.NumericDateFromFloat(f)
	if err != nil {
		t.Fatalf("NumericDateFromFloat(%v): %v", f, err)
	}
	return d
}

func TestNumericDateCompare(t *testing.T) {
	for _, tc := range []struct {
		name string
		date *cwt.NumericDate
		at   time.Time
		want int
	}{
		{"integer date, a nanosecond before", cwt.NewNumericDate(1000), time.Unix(999, 999999999), -1},
		{"integer date, exactly", cwt.NewNumericDate(1000), time.Unix(1000, 0), 0},
		{"integer date, a nanosecond after", cwt.NewNumericDate(1000), time.Unix(1000, 1), 1},
		{"fractional date, a whole second before", floatDate(t, 1000.5), time.Unix(1000, 0), -1},
		{"fractional date, a nanosecond before", floatDate(t, 1000.5), time.Unix(1000, 499999999), -1},
		{"fractional date, exactly", floatDate(t, 1000.5), time.Unix(1000, 500000000), 0},
		{"fractional date, a nanosecond after", floatDate(t, 1000.5), time.Unix(1000, 500000001), 1},
		{"fractional date, the next second", floatDate(t, 1000.5), time.Unix(1001, 0), 1},
		{"negative fractional date, exactly", floatDate(t, -1.5), time.Unix(-2, 500000000), 0},
		{"negative fractional date, a nanosecond before", floatDate(t, -1.5), time.Unix(-2, 499999999), -1},
	} {
		if got := tc.date.Compare(tc.at); got != tc.want {
			t.Errorf("%s: Compare = %d, want %d", tc.name, got, tc.want)
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
		d := floatDate(t, tc.in)
		if d.Unix() != tc.wantSec || d.Fraction() != tc.wantFrac {
			t.Errorf("NumericDateFromFloat(%v) = (%d, %v), want (%d, %v)", tc.in, d.Unix(), d.Fraction(), tc.wantSec, tc.wantFrac)
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
		if _, err := cwt.NumericDateFromFloat(tc.in); !errors.Is(err, tc.want) {
			t.Errorf("NumericDateFromFloat(%v) = %v, want an error wrapping %v", tc.in, err, tc.want)
		}
	}
}

// A tiny negative date's fraction rounds to 1 in float64; it must stay below 1 and still compare correctly.
func TestNumericDateFromATinyNegativeFloat(t *testing.T) {
	d := floatDate(t, -1e-300)
	if d.Unix() != -1 || !(d.Fraction() >= 0 && d.Fraction() < 1) {
		t.Fatalf("NumericDateFromFloat(-1e-300) = (%d, %v), want -1 and a fraction in [0, 1)", d.Unix(), d.Fraction())
	}
	if got := d.Compare(time.Unix(0, 0)); got != 1 {
		t.Errorf("Compare(epoch) = %d, want 1: the epoch is after a date just below it", got)
	}
	if got := d.Compare(time.Unix(-1, 999999999)); got != -1 {
		t.Errorf("Compare(epoch minus 1 ns) = %d, want -1", got)
	}
}
