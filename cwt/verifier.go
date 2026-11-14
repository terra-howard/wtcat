package cwt

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// Algorithm is a COSE algorithm identifier (RFC 9053) that this package can verify.
type Algorithm int64

// Algorithms this package verifies. HMAC algorithms mean COSE_Mac0; signature algorithms mean COSE_Sign1.
const (
	HMAC256x64  Algorithm = algHMAC256x64
	HMAC256x256 Algorithm = algHMAC256x256
	ES256       Algorithm = algES256
	PS256       Algorithm = algPS256
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
	alg := Algorithm(msg.alg)
	if !slices.Contains(v.Algorithms, alg) {
		return nil, unsupported("algorithm %d is not in the Verifier's allow-list", msg.alg)
	}
	isMAC := alg == HMAC256x64 || alg == HMAC256x256
	isSig := alg == ES256 || alg == PS256
	switch {
	case !isMAC && !isSig:
		return nil, unsupported("algorithm %d", msg.alg)
	case isMAC && msg.coseTag == tagSign1, isSig && msg.coseTag == tagMac0:
		return nil, malformed("COSE tag %d does not match algorithm %d", msg.coseTag, msg.alg)
	}

	key, err := v.Key(msg.kid, alg)
	if err != nil {
		return nil, fmt.Errorf("%w: key lookup: %w", ErrVerification, err)
	}
	if isMAC {
		secret, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: an HMAC algorithm needs a []byte key, got %T", ErrVerification, key)
		}
		err = verifyMac0Message(msg, secret)
	} else {
		err = verifySign1Message(msg, key)
	}
	if err != nil {
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
