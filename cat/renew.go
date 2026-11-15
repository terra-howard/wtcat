package cat

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

// Issuance lets a Validator issue tokens: renewals under catr, and later tokens minted for catif (decision 0022).
type Issuance struct {
	Issuer string // written into iss; empty means renewed tokens carry no iss
	// Key returns the signing key for a kid; "" asks for the default renewal key.
	Key func(kid string) (cwt.SigningKey, error)
}

// RenewalType is how a renewed token reaches the client (section 4.9.2).
type RenewalType int

// Renewal types.
const (
	RenewAutomatic RenewalType = 0 // by the mechanism the token arrived in
	RenewCookie    RenewalType = 1
	RenewHeader    RenewalType = 2
	RenewRedirect  RenewalType = 3
)

// Renewal is a renewed token and how to convey it. Names left empty take the conveying code's defaults.
type Renewal struct {
	Token        string // the new token, base64url without padding
	Type         RenewalType
	CookieName   string
	CookieParams []string
	HeaderName   string
	HeaderParams []string
	Status       int // for redirect renewal: 300 to 399, 307 by default
}

// ErrNoRenewal means the token's catr cannot be followed: it is malformed, carries parameters inappropriate to its
// type, or asks for something this recipient cannot do. The token itself is unaffected (decision 0022).
var ErrNoRenewal = errors.New("cat: token not renewed")

// claimCatr is the catr claim key (section 4.9.2).
const claimCatr = 323

// catr holds a parsed catr claim.
type catr struct {
	typ          int64
	expadd       float64
	deadline     *float64
	cookieName   string
	headerName   string
	cookieParams []string
	headerParams []string
	status       int
}

// appropriate lists the parameters each renewal type may carry (section 4.9.2).
var appropriate = map[int64]map[int64]bool{
	0: {0: true, 1: true, 2: true, 3: true, 4: true, 7: true},
	1: {0: true, 1: true, 2: true, 3: true, 5: true},
	2: {0: true, 1: true, 2: true, 4: true, 6: true},
	3: {0: true, 1: true, 2: true, 7: true},
}

func noRenewal(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrNoRenewal}, args...)...)
}

// parseCatr parses a catr claim. It returns nil, nil for an unknown renewal type, which section 4.9.2.5 ignores.
func parseCatr(value cbor.RawMessage) (*catr, error) {
	var m map[any]cbor.RawMessage
	if err := decMode.Unmarshal(value, &m); err != nil || m == nil {
		return nil, noRenewal("catr is not a map")
	}
	r := &catr{}
	params := map[int64]cbor.RawMessage{}
	for k, v := range m {
		key, ok := k.(uint64)
		if !ok || key > 7 {
			return nil, noRenewal("catr has parameter %v, which this version does not know", k)
		}
		params[int64(key)] = v
	}
	typ, ok := params[0]
	if !ok || decMode.Unmarshal(typ, &r.typ) != nil || majorType(typ) > majorNegative {
		return nil, noRenewal("catr has no integer type")
	}
	allowed, known := appropriate[r.typ]
	if !known {
		return nil, nil
	}
	for key := range params {
		if !allowed[key] {
			return nil, noRenewal("catr parameter %d is not appropriate to renewal type %d", key, r.typ)
		}
	}
	number := func(raw cbor.RawMessage) (float64, bool) {
		var f float64
		if raw == nil || majorType(raw) == majorText || majorType(raw) >= majorArray && majorType(raw) != majorSimple || decMode.Unmarshal(raw, &f) != nil {
			return 0, false
		}
		return f, !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 && f <= 1e12
	}
	if r.expadd, ok = number(params[1]); !ok {
		return nil, noRenewal("catr has no usable expadd")
	}
	if raw, present := params[2]; present {
		d, ok := number(raw)
		if !ok {
			return nil, noRenewal("catr deadline is not a usable number")
		}
		r.deadline = &d
	}
	var err error
	for key, dst := range map[int64]*string{3: &r.cookieName, 4: &r.headerName} {
		if raw, present := params[key]; present {
			s, e := textClaim(raw, claimCatr)
			if e != nil {
				return nil, noRenewal("catr parameter %d is not a text string", key)
			}
			*dst = *s
		}
	}
	for key, dst := range map[int64]*[]string{5: &r.cookieParams, 6: &r.headerParams} {
		if raw, present := params[key]; present {
			var items []cbor.RawMessage
			if majorType(raw) != majorArray || decMode.Unmarshal(raw, &items) != nil {
				return nil, noRenewal("catr parameter %d is not an array", key)
			}
			for _, item := range items {
				s, e := textClaim(item, claimCatr)
				if e != nil {
					return nil, noRenewal("catr parameter %d holds something other than text strings", key)
				}
				*dst = append(*dst, *s)
			}
		}
	}
	if raw, present := params[7]; present {
		var status uint64
		if majorType(raw) != majorUnsigned || decMode.Unmarshal(raw, &status) != nil || status < 300 || status > 399 {
			return nil, noRenewal("catr redirect status is not between 300 and 399")
		}
		r.status = int(status)
	} else if r.typ == 0 || r.typ == 3 {
		r.status = 307
	}
	return r, err
}

// renewEncoder writes the renewed claim set deterministically: shortest floats, and claims kept as received.
var renewEncoder = func() cbor.EncMode {
	em, err := cbor.EncOptions{ShortestFloat: cbor.ShortestFloat16}.EncMode()
	if err != nil {
		panic(err)
	}
	return em
}()

// Renew issues a renewed token for an acceptable token whose catr asks for one (section 4.9.2, decision 0022). It
// returns nil and no error when there is nothing to do: no catr, no Issuance, an unknown renewal type, or a time
// before the renewal deadline. A catr it cannot follow gives ErrNoRenewal.
func (v *Validator) Renew(t *Token, now time.Time) (*Renewal, error) {
	if v.Issuance == nil || t == nil || t.Claims.catr == nil {
		return nil, nil
	}
	r, err := parseCatr(t.Claims.catr)
	if err != nil || r == nil {
		return nil, err
	}
	if r.deadline != nil {
		if t.Claims.Expiry == nil {
			return nil, noRenewal("catr has a deadline but the token has no exp")
		}
		renewFrom := float64(t.Claims.Expiry.Unix()) + t.Claims.Expiry.Fraction() - *r.deadline
		if float64(now.UnixNano())/1e9 < renewFrom {
			return nil, nil
		}
	}

	var claims map[any]cbor.RawMessage
	if err := decMode.Unmarshal(t.payload, &claims); err != nil {
		return nil, noRenewal("the received claim set: %v", err)
	}
	set := func(key uint64, value any) error {
		b, err := renewEncoder.Marshal(value)
		claims[key] = b
		return err
	}
	var exp any = float64(now.Unix()) + r.expadd
	if r.expadd == math.Trunc(r.expadd) {
		exp = now.Unix() + int64(r.expadd)
	}
	if err := set(claimExp, exp); err != nil {
		return nil, err
	}
	if err := set(claimIat, now.Unix()); err != nil {
		return nil, err
	}
	delete(claims, uint64(claimIss))
	if v.Issuance.Issuer != "" {
		if err := set(claimIss, v.Issuance.Issuer); err != nil {
			return nil, err
		}
	}
	if t.Claims.CWTID != nil {
		cti := make([]byte, 16)
		if _, err := rand.Read(cti); err != nil {
			return nil, err
		}
		if err := set(claimCti, cti); err != nil {
			return nil, err
		}
	}
	payload, err := renewEncoder.Marshal(claims)
	if err != nil {
		return nil, err
	}
	if v.Issuance.Key == nil {
		return nil, noRenewal("Issuance has no key function")
	}
	key, err := v.Issuance.Key("")
	if err != nil {
		return nil, noRenewal("no renewal key: %v", err)
	}
	raw, err := cwt.Issue(payload, key)
	if err != nil {
		return nil, noRenewal("issuing: %v", err)
	}
	return &Renewal{
		Token: base64.RawURLEncoding.EncodeToString(raw), Type: RenewalType(r.typ),
		CookieName: r.cookieName, CookieParams: r.cookieParams,
		HeaderName: r.headerName, HeaderParams: r.headerParams, Status: r.status,
	}, nil
}
