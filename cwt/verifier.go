package cwt

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// KeyFunc returns the key for a token's kid (nil if the token has none) and algorithm: a []byte for HMAC
// algorithms, or a public key (*ecdsa.PublicKey for ES256, *rsa.PublicKey for PS256) for signature algorithms.
type KeyFunc func(kid []byte, alg Algorithm) (any, error)

// ErrMissingExpiry means RequireExpiry is set and the token has no exp claim.
var ErrMissingExpiry = errors.New("cwt: token has no exp")

// Verifier verifies CWTs against an allow-list of algorithms, a key lookup and a clock (decision 0012).
type Verifier struct {
	Algorithms    []Algorithm      // required: tokens with any other algorithm are rejected before key lookup
	Key           KeyFunc          // required
	Now           func() time.Time // optional; time.Now when nil
	Leeway        time.Duration    // allowance for clock skew on exp and nbf
	RequireExpiry bool             // reject tokens without exp
}

// Verify checks a token's algorithm, authenticity and validity window, and returns its claims.
func (v *Verifier) Verify(token []byte) (*Claims, error) {
	if len(v.Algorithms) == 0 {
		return nil, errors.New("cwt: Verifier has no algorithms")
	}
	if v.Key == nil {
		return nil, errors.New("cwt: Verifier has no key function")
	}
	msg, err := parseCOSE(token, 0)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(v.Algorithms, msg.alg) {
		return nil, unsupported("%v is not in the Verifier's allow-list", msg.alg)
	}
	if !msg.alg.known() {
		return nil, unsupported("%v", msg.alg)
	}
	if err := checkTagAgrees(msg.coseTag, msg.alg); err != nil {
		return nil, err
	}

	key, err := v.Key(msg.kid, msg.alg)
	if err != nil {
		return nil, fmt.Errorf("%w: key lookup: %w", ErrVerification, err)
	}
	if err := verifyWith(msg, msg.alg, key); err != nil {
		return nil, err
	}

	claims, err := claimsFromPayload(msg.payload)
	if err != nil {
		return nil, err
	}
	if v.RequireExpiry && claims.Expiry == nil {
		return nil, ErrMissingExpiry
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if err := claims.CheckTime(now(), v.Leeway); err != nil {
		return nil, err
	}
	return claims, nil
}
