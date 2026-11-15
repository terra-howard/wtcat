package cwt

import (
	"math"
	"time"
)

// NumericDate is a CWT date (RFC 8392 Section 2): seconds since 1970-01-01T00:00:00Z, ignoring leap seconds. It
// holds a date encoded as an integer or as a floating-point number exactly (decision 0016).
type NumericDate struct {
	sec  int64   // the date rounded toward negative infinity
	frac float64 // what remains, in [0, 1); zero for an integer date
}

// NewNumericDate returns a whole-second date.
func NewNumericDate(sec int64) *NumericDate { return &NumericDate{sec: sec} }

// Unix returns the date's whole seconds, rounded toward negative infinity.
func (d NumericDate) Unix() int64 { return d.sec }

// Fraction returns the part of the date after Unix, in [0, 1). It is zero for an integer date.
func (d NumericDate) Fraction() float64 { return d.frac }

// Compare returns -1, 0 or +1 as t is before, at or after the date, to the nanosecond.
func (d NumericDate) Compare(t time.Time) int {
	switch sec := t.Unix(); {
	case sec < d.sec:
		return -1
	case sec > d.sec:
		return 1
	}
	ns, fracNS := float64(t.Nanosecond()), d.frac*1e9
	switch {
	case ns < fracNS:
		return -1
	case ns > fracNS:
		return 1
	}
	return 0
}

// NumericDateFromFloat converts a floating-point date exactly. NaN and infinities are malformed (ErrMalformed), and
// dates outside the range of 64-bit seconds are unsupported (ErrUnsupported).
func NumericDateFromFloat(f float64) (*NumericDate, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, malformed("date %v is not finite", f)
	}
	floor := math.Floor(f)
	if floor < math.MinInt64 || floor >= math.MaxInt64 { // MaxInt64 rounds up to 2^63 as a float64
		return nil, unsupported("date %v is outside the range of 64-bit seconds", f)
	}
	frac := f - floor
	if frac >= 1 { // a tiny negative date, whose fraction rounds to 1; keep it below 1
		frac = math.Nextafter(1, 0)
	}
	return &NumericDate{sec: int64(floor), frac: frac}, nil
}
