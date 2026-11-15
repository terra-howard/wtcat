package cwt

import (
	"errors"
	"time"
)

var (
	// ErrExpired means the current time is at or after exp, after leeway (RFC 7519 Section 4.1.4).
	ErrExpired = errors.New("cwt: token expired")
	// ErrNotYetValid means the current time is before nbf, after leeway (RFC 7519 Section 4.1.5).
	ErrNotYetValid = errors.New("cwt: token not yet valid")
)

// CheckTime checks exp and nbf against now, allowing leeway for clock skew (decision 0010). Absent claims are not
// checked, and iat is never checked. Leeway counts in whole seconds, rounded down. Fractional dates are compared
// exactly (decision 0016).
func (c *Claims) CheckTime(now time.Time, leeway time.Duration) error {
	if leeway < 0 {
		return errors.New("cwt: leeway must not be negative")
	}
	slack := leeway.Truncate(time.Second)
	// Expired when now >= exp + slack, that is, when now - slack is at or after exp.
	if c.Expiry != nil && c.Expiry.Compare(now.Add(-slack)) >= 0 {
		return ErrExpired
	}
	// Not yet valid when now < nbf - slack, that is, when now + slack is before nbf.
	if c.NotBefore != nil && c.NotBefore.Compare(now.Add(slack)) < 0 {
		return ErrNotYetValid
	}
	return nil
}
