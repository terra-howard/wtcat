package cat

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

// NumericDate is a CWT date, held exactly whether encoded as an integer or a float. It is package cwt's type
// (decision 0016), so a date read by either package means the same thing.
type NumericDate = cwt.NumericDate

// Claims are the decoded claims a caller can read. Absent claims are nil, except Version. Other claims this package
// enforces, such as catu, catnip and cnf, are kept unexported.
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

	// The claims below are enforced but not exposed; each is nil when absent.
	jkt       []byte           // cnf (8): its jkt, the thumbprint of the key a DPoP proof must use
	replay    *uint64          // catreplay (308)
	network   []netMatch       // catnip (311)
	uri       []componentMatch // catu (312)
	alpns     [][]byte         // catalpn (314)
	headers   []headerMatch    // cath (315)
	countries []string         // catgeoiso3166 (316)
	geohashes []string         // geohash (282), lower case; empty but not nil for an empty array
	geocoords []geocoord       // catgeocoord (317)
	encrypted bool             // the claim set arrived in an encrypted token (decision 0030)
	moqt      []moqtScope      // the moqt claim's scopes (decision 0035)
	hasMOQT   bool             // the token has a moqt claim
	// moqtUnknownKey reports a moqt claim with a key other than 0, which makes the claim set unacceptable.
	moqtUnknownKey bool
	tpk            []byte          // cattpk (319)
	dpopWindow     *uint64         // catdpop (321): its window setting, in seconds
	catif          cbor.RawMessage // catif (322) as received, parsed only for a response to a refusal
	catr           cbor.RawMessage // catr (323) as received, parsed only when renewal is attempted (decision 0022)
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

// Claim keys this package knows: RFC 8392's, then CTA-5007-B's (section 4.5).
const (
	claimIss           = 1
	claimSub           = 2
	claimAud           = 3
	claimExp           = 4
	claimNbf           = 5
	claimIat           = 6
	claimCti           = 7
	claimCnf           = 8
	claimGeohash       = 282
	claimCatgeocoord   = 317
	claimCatreplay     = 308
	claimCatv          = 310
	claimCatnip        = 311
	claimCatu          = 312
	claimCatm          = 313
	claimCatalpn       = 314
	claimCath          = 315
	claimCatgeoiso3166 = 316
	claimCattpk        = 319
	claimCatifdata     = 320
	claimCatdpop       = 321
	claimCatif         = 322
	claimCatr          = 323
)

// cnfJKT is the jkt confirmation method's key inside a cnf claim (section 4.8.1).
const cnfJKT = 323

// cborNull is the encoding of CBOR's null.
const cborNull = 0xf6

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
	majorMap      = 5
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
	return decodeClaimsIn(payload, false, defaultClaimKeys)
}

// claimKeys are the keys of claims whose keys are not yet assigned, which a Validator can set (decision 0035).
type claimKeys struct{ moqt, moqtReval int64 }

var defaultClaimKeys = claimKeys{moqt: DefaultMOQTClaimKey, moqtReval: DefaultMOQTRevalKey}

// decodeClaimsIn is decodeClaims for a claim set that may have arrived encrypted, which lifts the limits sections
// 4.6.9, 4.6.15 and 4.6.16 set on unencrypted claims (decision 0030).
func decodeClaimsIn(payload []byte, encrypted bool, keys claimKeys) (*Claims, error) {
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
	c := &Claims{Version: 1, encrypted: encrypted}
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
		switch key {
		case keys.moqt:
			if len(value) > 0 && majorType(value) == majorTag {
				return nil, malformed("the moqt claim is tagged, which section 4.5 forbids")
			}
			scopes, unknown, err := decodeMOQT(value)
			if err != nil {
				return nil, err
			}
			c.moqt, c.moqtUnknownKey = scopes, unknown
			continue
		case keys.moqtReval:
			return nil, unsupported("moqt-reval (claim %d): revalidation is not supported yet (decision 0035)", key)
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
	case claimIss, claimSub, claimAud, claimExp, claimNbf, claimIat, claimCti, claimCnf, claimCatreplay, claimCatv,
		claimCatnip, claimCatu, claimCatm, claimCatalpn, claimCath, claimCatgeoiso3166, claimCattpk, claimCatdpop,
		claimCatif, claimCatr, claimGeohash, claimCatgeocoord:
	default:
		return nil // a claim this package does not know, or catifdata, which only means something in a minted token
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
		c.network, err = decodeCatnip(value, c.encrypted)
	case claimCatr:
		c.catr = value
	case claimCatif:
		c.catif = value
	case claimCatalpn:
		c.alpns, err = decodeALPNs(value)
	case claimCattpk:
		c.tpk, err = decodeTPK(value)
	case claimCatgeoiso3166:
		c.countries, err = decodeCountries(value)
	case claimGeohash:
		c.geohashes, err = decodeGeohashes(value, c.encrypted)
	case claimCatgeocoord:
		c.geocoords, err = decodeGeocoords(value, c.encrypted)
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

// isKind reports whether err already carries one of the kinds of invalid token.
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
		return cwt.NewNumericDate(int64(u)), nil
	case majorNegative:
		var i int64
		if err := decMode.Unmarshal(value, &i); err != nil { // only a value below -2^63 fails here
			return nil, unsupported("claim %d is outside the range of 64-bit seconds", key)
		}
		return cwt.NewNumericDate(i), nil
	case majorSimple:
		if info := value[0] & 0x1f; info < 25 || info > 27 {
			return nil, malformed("claim %d is not a date", key)
		}
		var f float64
		if err := decMode.Unmarshal(value, &f); err != nil {
			return nil, err
		}
		return cwt.NumericDateFromFloat(f)
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
			if kk > componentExtension {
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
		if key, ok := k.(uint64); !ok || key != cnfJKT {
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
