package cat

import (
	"fmt"
	"math"
	"time"

	"github.com/terra-howard/wtcat/cwt"
)

// NumericDate is a CWT date (RFC 8392 Section 2): seconds since 1970-01-01T00:00:00Z, ignoring leap seconds. It
// holds an integer or a floating-point date exactly, so that comparisons with no leeway (CTA-5007-B sections 4.6.3
// and 4.6.4) are exact too.
type NumericDate struct {
	sec  int64   // the date rounded toward negative infinity
	frac float64 // what remains, in [0, 1); zero for an integer date
}

// Unix returns the date's whole seconds, rounded toward negative infinity.
func (d NumericDate) Unix() int64 { return d.sec }

// Fraction returns the part of the date after Unix, in [0, 1). It is zero for an integer date.
func (d NumericDate) Fraction() float64 { return d.frac }

// compare returns -1, 0 or +1 as t is before, at or after the date, to the nanosecond.
func (d NumericDate) compare(t time.Time) int {
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

// dateFromFloat converts a floating-point date. NaN and infinities are malformed; a date outside the range of
// 64-bit seconds is unsupported (decision 0015).
func dateFromFloat(f float64) (NumericDate, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return NumericDate{}, fmt.Errorf("%w: date %v is not finite", cwt.ErrMalformed, f)
	}
	floor := math.Floor(f)
	if floor < math.MinInt64 || floor >= math.MaxInt64 { // MaxInt64 rounds up to 2^63 as a float64
		return NumericDate{}, fmt.Errorf("%w: date %v is outside the range of 64-bit seconds", cwt.ErrUnsupported, f)
	}
	frac := f - floor
	if frac >= 1 {
		// f is a tiny negative number, whose true fraction is just below 1 but rounds to 1 in float64. The largest
		// float64 below 1 compares the same way to the nanosecond and keeps the fraction in [0, 1). Found by fuzzing.
		frac = math.Nextafter(1, 0)
	}
	return NumericDate{sec: int64(floor), frac: frac}, nil
}
