package cat

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

// Claims are the claims phase 1 decodes (decision 0015). Absent claims are nil, except Version.
type Claims struct {
	Issuer    *string      // iss (1)
	Subject   *string      // sub (2)
	Audience  []string     // aud (3); a single string becomes one element, and an empty array a non-nil empty slice
	Expiry    *NumericDate // exp (4)
	NotBefore *NumericDate // nbf (5)
	IssuedAt  *NumericDate // iat (6); informational, never checked (section 4.7.2)
	CWTID     []byte       // cti (7); an empty byte string is a non-nil empty slice
	Version   uint64       // catv (310); 1 when absent (section 4.6.8)
	Methods   []string     // catm (313): the methods the token may be used with

	headers []headerMatch    // cath (315); nil when absent
	uri     []componentMatch // catu (312); nil when absent
	network []netMatch       // catnip (311); nil when absent
	jkt     []byte           // cnf (8) jkt (323); nil when cnf is absent
	// dpopWindow is the window setting of catdpop (321), in seconds; nil when absent.
	dpopWindow *uint64
	replay     *uint64 // catreplay (308); nil when absent
}

// componentMatch is one member of a catu claim: a URI component (0 to 8) and its match.
type componentMatch struct {
	component int64
	match     *match
}

// headerMatch is one member of a cath claim.
type headerMatch struct {
	name  string
	match *match
}

// Claim keys this package knows (section 4.5 and RFC 8392).
const (
	claimIss       = 1
	claimSub       = 2
	claimAud       = 3
	claimExp       = 4
	claimNbf       = 5
	claimIat       = 6
	claimCti       = 7
	claimCatv      = 310
	claimCnf       = 8
	claimCatreplay = 308
	claimCatnip    = 311
	claimCatdpop   = 321
	claimCatu      = 312
	claimCatm      = 313
	claimCath      = 315
)

// notYetEnforced lists the claims a recipient must support (section 4.5) that phase 1 does not enforce yet. A token
// carrying one is refused, never accepted with the restriction ignored (decision 0015).
var notYetEnforced = map[int64]string{} // none at present: phase 3 enforces cnf and catdpop

// decMode decodes claims strictly: duplicate map keys, invalid UTF-8 and indefinite lengths are refused.
var decMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		UTF8:        cbor.UTF8RejectInvalid,
		IndefLength: cbor.IndefLengthForbidden,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

// CBOR major types (RFC 8949 Section 3.1).
const (
	majorUnsigned = 0
	majorNegative = 1
	majorBytes    = 2
	majorText     = 3
	majorArray    = 4
	majorTag      = 6
	majorSimple   = 7
)

func majorType(b []byte) byte { return b[0] >> 5 }

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{cwt.ErrMalformed}, args...)...)
}

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{cwt.ErrUnsupported}, args...)...)
}

// decodeClaims decodes a verified payload as a CAT claim set. Claims it does not know are ignored, whatever their
// key or value (sections 4.3.1.5 and 4.5); claims it knows must have the right type and no tag (section 4.5).
func decodeClaims(payload []byte) (*Claims, error) {
	if len(payload) > 0 && majorType(payload) == majorTag {
		return nil, unsupported("nested CWT")
	}
	var m map[any]cbor.RawMessage
	if err := decMode.Unmarshal(payload, &m); err != nil {
		return nil, malformed("claim set: %v", err)
	}
	if m == nil {
		return nil, malformed("claim set is not a map")
	}
	c := &Claims{Version: 1}
	for k, value := range m {
		var key int64
		switch v := k.(type) {
		case uint64:
			if v > math.MaxInt64 {
				continue // an integer key no claim here uses
			}
			key = int64(v)
		case int64:
			key = v
		case string:
			continue // a text-keyed claim is one this package does not understand
		default:
			return nil, malformed("claim key of type %T", k)
		}
		if name, ok := notYetEnforced[key]; ok {
			return nil, unsupported("claim %d (%s) must be enforced, and this version does not enforce it yet", key, name)
		}
		if err := c.decodeClaim(key, value); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// decodeClaim decodes one claim value into c if the key is one this package knows.
func (c *Claims) decodeClaim(key int64, value cbor.RawMessage) error {
	switch key {
	case claimIss, claimSub, claimAud, claimExp, claimNbf, claimIat, claimCti, claimCatv, claimCatm, claimCath, claimCatu, claimCatnip, claimCnf, claimCatdpop, claimCatreplay:
	default:
		return nil
	}
	if len(value) == 0 {
		return malformed("claim %d is empty", key)
	}
	if majorType(value) == majorTag {
		return malformed("claim %d is tagged, which section 4.5 forbids", key)
	}
	var err error
	switch key {
	case claimIss:
		c.Issuer, err = textClaim(value, key)
	case claimSub:
		c.Subject, err = textClaim(value, key)
	case claimAud:
		c.Audience, err = decodeAudience(value)
	case claimExp:
		c.Expiry, err = decodeDate(value, key)
	case claimNbf:
		c.NotBefore, err = decodeDate(value, key)
	case claimIat:
		c.IssuedAt, err = decodeDate(value, key)
	case claimCti:
		if majorType(value) != majorBytes {
			return malformed("claim 7 (cti) is not a byte string")
		}
		err = decMode.Unmarshal(value, &c.CWTID)
	case claimCatm:
		c.Methods, err = textArray(value, key)
	case claimCath:
		c.headers, err = decodeCath(value)
	case claimCatu:
		c.uri, err = decodeCatu(value)
	case claimCatnip:
		c.network, err = decodeCatnip(value)
	case claimCatreplay:
		if majorType(value) != majorUnsigned {
			return malformed("claim 308 (catreplay) is not an unsigned integer")
		}
		c.replay = new(uint64)
		err = decMode.Unmarshal(value, c.replay)
	case claimCnf:
		c.jkt, err = decodeCnf(value)
	case claimCatdpop:
		c.dpopWindow, err = decodeCatdpop(value)
	case claimCatv:
		if majorType(value) != majorUnsigned {
			return malformed("claim 310 (catv) is not an unsigned integer")
		}
		if err = decMode.Unmarshal(value, &c.Version); err == nil && c.Version != 1 {
			return unsupported("catv %d; this version supports 1", c.Version)
		}
	}
	if err != nil && !isKind(err) {
		err = malformed("claim %d: %v", key, err)
	}
	return err
}

func isKind(err error) bool {
	return errors.Is(err, cwt.ErrMalformed) || errors.Is(err, cwt.ErrUnsupported)
}

func textClaim(value cbor.RawMessage, key int64) (*string, error) {
	if majorType(value) != majorText {
		return nil, malformed("claim %d is not a text string", key)
	}
	var s string
	if err := decMode.Unmarshal(value, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// decodeAudience accepts a text string or an array of text strings, none tagged (section 4.6.2).
func decodeAudience(value cbor.RawMessage) ([]string, error) {
	switch majorType(value) {
	case majorText:
		s, err := textClaim(value, claimAud)
		if err != nil {
			return nil, err
		}
		return []string{*s}, nil
	case majorArray:
		var items []cbor.RawMessage
		if err := decMode.Unmarshal(value, &items); err != nil {
			return nil, err
		}
		out := make([]string, 0, len(items))
		for _, item := range items {
			if len(item) == 0 || majorType(item) != majorText {
				return nil, malformed("claim 3 (aud) holds something other than an untagged text string")
			}
			s, err := textClaim(item, claimAud)
			if err != nil {
				return nil, err
			}
			out = append(out, *s)
		}
		return out, nil
	default:
		return nil, malformed("claim 3 (aud) is neither a text string nor an array")
	}
}

// decodeDate accepts an integer or a floating-point NumericDate (RFC 8392 Section 2).
func decodeDate(value cbor.RawMessage, key int64) (*NumericDate, error) {
	switch majorType(value) {
	case majorUnsigned:
		var u uint64
		if err := decMode.Unmarshal(value, &u); err != nil {
			return nil, err
		}
		if u > math.MaxInt64 {
			return nil, unsupported("claim %d is outside the range of 64-bit seconds", key)
		}
		return &NumericDate{sec: int64(u)}, nil
	case majorNegative:
		var i int64
		if err := decMode.Unmarshal(value, &i); err != nil { // only a value below -2^63 fails here
			return nil, unsupported("claim %d is outside the range of 64-bit seconds", key)
		}
		return &NumericDate{sec: i}, nil
	case majorSimple:
		if info := value[0] & 0x1f; info < 25 || info > 27 {
			return nil, malformed("claim %d is not a date", key)
		}
		var f float64
		if err := decMode.Unmarshal(value, &f); err != nil {
			return nil, err
		}
		d, err := dateFromFloat(f)
		if err != nil {
			return nil, err
		}
		return &d, nil
	default:
		return nil, malformed("claim %d is not a date", key)
	}
}

// textArray decodes an array of at least one untagged text string, the shape of catm (section 4.6.11).
func textArray(value cbor.RawMessage, key int64) ([]string, error) {
	if majorType(value) != majorArray {
		return nil, malformed("claim %d is not an array", key)
	}
	var items []cbor.RawMessage
	if err := decMode.Unmarshal(value, &items); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, malformed("claim %d is an empty array", key)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, err := textClaim(item, key)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, nil
}

// decodeCath decodes a cath claim: header names to matches (section 4.6.13). Two names equal but for case make
// the claim malformed (decision 0017).
func decodeCath(value cbor.RawMessage) ([]headerMatch, error) {
	var m map[any]cbor.RawMessage
	if err := decMode.Unmarshal(value, &m); err != nil || m == nil {
		return nil, malformed("claim 315 (cath) is not a map")
	}
	out := make([]headerMatch, 0, len(m))
	seen := map[string]bool{}
	for k, v := range m {
		name, ok := k.(string)
		if !ok {
			return nil, malformed("claim 315 (cath) has a key of type %T", k)
		}
		folded := strings.ToLower(name)
		if seen[folded] {
			return nil, malformed("claim 315 (cath) names header %q twice, ignoring case", name)
		}
		seen[folded] = true
		hm, err := decodeMatch(v, "cath "+name)
		if err != nil {
			return nil, err
		}
		out = append(out, headerMatch{name: name, match: hm})
	}
	return out, nil
}

// decodeCatu decodes a catu claim: URI components to matches (section 4.6.10). A component other than 0 to 8
// cannot be checked, so the token is unsupported.
func decodeCatu(value cbor.RawMessage) ([]componentMatch, error) {
	var m map[any]cbor.RawMessage
	if err := decMode.Unmarshal(value, &m); err != nil || m == nil {
		return nil, malformed("claim 312 (catu) is not a map")
	}
	out := make([]componentMatch, 0, len(m))
	for k, v := range m {
		var component int64
		switch kk := k.(type) {
		case uint64:
			if kk > 8 {
				return nil, unsupported("claim 312 (catu) has URI component %d", kk)
			}
			component = int64(kk)
		case int64:
			return nil, unsupported("claim 312 (catu) has URI component %d", kk)
		default:
			return nil, malformed("claim 312 (catu) has a key of type %T", k)
		}
		cm, err := decodeMatch(v, fmt.Sprintf("catu component %d", component))
		if err != nil {
			return nil, err
		}
		out = append(out, componentMatch{component: component, match: cm})
	}
	return out, nil
}

// decodeCnf decodes a cnf claim, which must hold a 32-byte jkt and no confirmation method this version cannot
// check (decision 0020).
func decodeCnf(value cbor.RawMessage) ([]byte, error) {
	var m map[any]cbor.RawMessage
	if err := decMode.Unmarshal(value, &m); err != nil || m == nil {
		return nil, malformed("claim 8 (cnf) is not a map")
	}
	var jkt []byte
	for k, v := range m {
		if key, ok := k.(uint64); !ok || key != 323 {
			return nil, unsupported("claim 8 (cnf) has confirmation method %v, which this version cannot check", k)
		}
		if len(v) == 0 || majorType(v) != majorBytes {
			return nil, malformed("cnf jkt is not an untagged byte string")
		}
		if err := decMode.Unmarshal(v, &jkt); err != nil || len(jkt) != 32 {
			return nil, malformed("cnf jkt is not 32 bytes")
		}
	}
	if jkt == nil {
		return nil, unsupported("claim 8 (cnf) has no jkt, the only confirmation method this version checks")
	}
	return jkt, nil
}

// decodeCatdpop decodes the settings of catdpop (section 4.8.2): crit (-1), window (0) and jti (1). jti never
// causes a refusal (decision 0020), and other settings are ignored unless listed as critical.
func decodeCatdpop(value cbor.RawMessage) (*uint64, error) {
	var m map[any]cbor.RawMessage
	if err := decMode.Unmarshal(value, &m); err != nil || m == nil {
		return nil, malformed("claim 321 (catdpop) is not a map")
	}
	var window *uint64
	for k, v := range m {
		var key int64
		switch kk := k.(type) {
		case uint64:
			if kk > 1 {
				continue // a setting this version does not know, unless crit lists it
			}
			key = int64(kk)
		case int64:
			key = kk
		default:
			return nil, malformed("claim 321 (catdpop) has a key of type %T", k)
		}
		if len(v) == 0 || majorType(v) == majorTag {
			return nil, malformed("catdpop setting %d is tagged", key)
		}
		switch key {
		case -1:
			var crit []int64
			if majorType(v) != majorArray || decMode.Unmarshal(v, &crit) != nil {
				return nil, malformed("catdpop crit is not an array of integers")
			}
			for _, c := range crit {
				if c >= -1 && c <= 1 {
					return nil, malformed("catdpop crit lists %d, which is always understood", c)
				}
			}
			if len(crit) > 0 {
				return nil, unsupported("catdpop crit lists setting %d, which this version does not know", crit[0])
			}
		case 0, 1:
			var u uint64
			if majorType(v) != majorUnsigned || decMode.Unmarshal(v, &u) != nil {
				return nil, malformed("catdpop setting %d is not an unsigned integer", key)
			}
			if key == 0 {
				window = &u
			}
		}
	}
	return window, nil
}
