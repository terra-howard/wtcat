package cat

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/terra-howard/wtcat/cwt"
)

// Errors for tokens that are valid but not acceptable (section 4.3.1.2). Each wraps ErrUnacceptable. Invalid tokens
// carry cwt.ErrMalformed, cwt.ErrVerification or cwt.ErrUnsupported instead (decision 0015).
var (
	ErrUnacceptable = errors.New("cat: token is valid but not acceptable")
	ErrExpired      = fmt.Errorf("%w: expired", ErrUnacceptable)
	ErrNotYetValid  = fmt.Errorf("%w: not yet valid", ErrUnacceptable)
	ErrIssuer       = fmt.Errorf("%w: iss is not the issuer of the key that verified the token", ErrUnacceptable)
	ErrAudience     = fmt.Errorf("%w: aud does not name this recipient", ErrUnacceptable)
	ErrReplay       = fmt.Errorf("%w: catreplay forbids reuse, and the cti was seen before", ErrUnacceptable)
)

// Token length limits (section 4.3.1.1).
const (
	MinLength        = 4096 // recipients must process tokens of this many bytes
	DefaultMaxLength = 8192 // a common limit for one HTTP header line
)

// Key is a verification key: the one algorithm it may be used with, its material, and the issuer it belongs to.
type Key struct {
	cwt.Key
	// Issuer is the issuer this key belongs to. A token with an iss claim is acceptable only if iss equals it
	// (section 4.6.1); when Issuer is empty, the key belongs to no issuer and any iss is refused.
	Issuer string
}

// KeyFunc returns the key for a token's kid, which is nil when the token has none. A recipient that refuses
// tokens without a kid (section 4.3.1.1.1 allows it) returns an error for nil.
type KeyFunc func(kid []byte) (Key, error)

// Validator validates CATs: phase 1 of decision 0015.
type Validator struct {
	Keys      KeyFunc          // required
	Audiences []string         // the names this recipient answers to; a token's aud must name one of them
	Now       func() time.Time // optional; time.Now when nil
	MaxLength int              // the longest token text accepted, in bytes; 0 means DefaultMaxLength, else at least MinLength
	// DPoPWindow is how far the iat of a DPoP proof may be from now, either way, when catdpop sets no window;
	// 0 means DefaultDPoPWindow (decision 0020).
	DPoPWindow time.Duration
	// Replay, if set, records a cti and reports whether it had been seen before, for catreplay (decision 0021). It
	// is called only for tokens that pass every other check and whose catreplay is not 0.
	Replay func(cti []byte) (seen bool)
}

// Token is a CAT that is valid and acceptable.
type Token struct {
	Algorithm cwt.Algorithm
	KID       []byte
	Claims    Claims
}

// Validate checks that a token, in its text form, is valid and acceptable to this recipient now, and returns it.
//
// Valid means base64url within the length limit, deterministically encoded, verified with the key for its kid,
// and carrying claims of the right syntax, none of them a required claim this version does not yet enforce.
// Acceptable means iss names the key's issuer, aud names this recipient, and the current time is before exp and
// not before nbf, with no leeway. Absent claims are not checked. Claims this version does not support are
// ignored, as section 4.5 requires; the package documentation lists those it enforces.
func (v *Validator) Validate(token string) (*Token, error) { return v.validate(token, nil) }

func (v *Validator) validate(token string, req *Request) (*Token, error) {
	if v.Keys == nil {
		return nil, errors.New("cat: Validator has no key function")
	}
	maxLen := v.MaxLength
	switch {
	case maxLen == 0:
		maxLen = DefaultMaxLength
	case maxLen < MinLength:
		return nil, fmt.Errorf("cat: MaxLength %d is below the %d bytes CTA-5007-B requires recipients to accept", maxLen, MinLength)
	}

	data, err := decodeText(token, maxLen)
	if err != nil {
		return nil, err
	}
	if err := checkDeterministic(data); err != nil {
		return nil, err
	}
	var issuer string
	msg, err := cwt.VerifyMessage(data, func(kid []byte) (cwt.Key, error) {
		k, err := v.Keys(kid)
		issuer = k.Issuer
		return k.Key, err
	})
	if err != nil {
		return nil, err
	}
	if len(msg.Protected) > 0 {
		if err := checkDeterministic(msg.Protected); err != nil {
			return nil, fmt.Errorf("protected header: %w", err)
		}
	}
	if err := checkDeterministic(msg.Payload); err != nil {
		return nil, fmt.Errorf("claim set: %w", err)
	}
	claims, err := decodeClaims(msg.Payload)
	if err != nil {
		return nil, err
	}

	if claims.Issuer != nil && (issuer == "" || *claims.Issuer != issuer) {
		return nil, ErrIssuer
	}
	if claims.Audience != nil && !slices.ContainsFunc(claims.Audience, func(a string) bool { return slices.Contains(v.Audiences, a) }) {
		return nil, ErrAudience
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	t := now()
	if claims.Expiry != nil && claims.Expiry.compare(t) >= 0 {
		return nil, ErrExpired
	}
	if claims.NotBefore != nil && claims.NotBefore.compare(t) < 0 {
		return nil, ErrNotYetValid
	}
	if err := checkRequest(claims, req); err != nil {
		return nil, err
	}
	if err := v.checkConfirmation(claims, req, token, t); err != nil {
		return nil, err
	}
	if err := checkLocation(claims, req); err != nil {
		return nil, err
	}
	if err := checkConnection(claims, req); err != nil {
		return nil, err
	}
	// Last, so that a refused token never uses up its cti. Values above 2 are undefined and treated as 1.
	if claims.replay != nil && *claims.replay != 0 && claims.CWTID != nil && v.Replay != nil && v.Replay(claims.CWTID) {
		return nil, ErrReplay
	}
	return &Token{Algorithm: msg.Algorithm, KID: msg.KID, Claims: *claims}, nil
}
