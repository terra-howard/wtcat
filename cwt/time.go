package cwt

import (
	"errors"
	"math"
	"time"
)

var (
	// ErrExpired means the current time is at or after exp, after leeway (RFC 7519 Section 4.1.4).
	ErrExpired = errors.New("cwt: token expired")
	// ErrNotYetValid means the current time is before nbf, after leeway (RFC 7519 Section 4.1.5).
	ErrNotYetValid = errors.New("cwt: token not yet valid")
)

// CheckTime checks exp and nbf against now, allowing leeway for clock skew (decision 0010). Absent claims are not
// checked, and iat is never checked. Leeway counts in whole seconds, rounded down.
func (c *Claims) CheckTime(now time.Time, leeway time.Duration) error {
	if leeway < 0 {
		return errors.New("cwt: leeway must not be negative")
	}
	nowSec := now.Unix()
	slack := int64(leeway / time.Second)
	if c.Expiry != nil {
		// Expired when now >= exp + slack. If exp + slack would overflow, the bound is beyond any time.
		if *c.Expiry <= math.MaxInt64-slack && nowSec >= *c.Expiry+slack {
			return ErrExpired
		}
	}
	if c.NotBefore != nil {
		// Not yet valid when now < nbf - slack. If nbf - slack would overflow, the bound is before any time.
		if *c.NotBefore >= math.MinInt64+slack && nowSec < *c.NotBefore-slack {
			return ErrNotYetValid
		}
	}
	return nil
}
