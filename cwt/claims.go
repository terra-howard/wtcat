package cwt

import (
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"
)

// decMode is the strict decoder used everywhere in this package (decision 0008): duplicate map keys and invalid
// UTF-8 are rejected; indefinite-length items are allowed.
var decMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		UTF8:        cbor.UTF8RejectInvalid,
		IndefLength: cbor.IndefLengthAllowed,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

// CBOR major types, from the top three bits of an item's first byte (RFC 8949 Section 3.1).
const (
	majorUnsigned = 0
	majorNegative = 1
	majorBytes    = 2
	majorText     = 3
	majorArray    = 4
	majorTag      = 6
	majorSimple   = 7
)

func majorType(raw []byte) byte { return raw[0] >> 5 }

// isFloat reports whether a major type 7 item is a half, single or double precision float.
func isFloat(raw []byte) bool {
	info := raw[0] & 0x1f
	return majorType(raw) == majorSimple && (info == 25 || info == 26 || info == 27)
}

// DecodeClaims decodes an unprotected CWT Claims Set.
func DecodeClaims(data []byte) (*Claims, error) {
	var m map[any]cbor.RawMessage
	if err := decMode.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: claims set: %v", ErrMalformed, err)
	}
	if m == nil {
		return nil, fmt.Errorf("%w: claims set is not a map", ErrMalformed)
	}
	c := &Claims{}
	for k, raw := range m {
		key, err := claimKey(k)
		if err != nil {
			return nil, err
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("%w: claim %d is empty", ErrMalformed, key)
		}
		if key >= 1 && key <= 7 && majorType(raw) == majorTag {
			return nil, fmt.Errorf("%w: claim %d is tagged, which RFC 8392 Section 3 forbids", ErrMalformed, key)
		}
		switch key {
		case 1:
			err = decodeText(raw, key, &c.Issuer)
		case 2:
			err = decodeText(raw, key, &c.Subject)
		case 3:
			c.Audience, err = decodeAudience(raw)
		case 4:
			c.Expiry, err = decodeDate(raw, key)
		case 5:
			c.NotBefore, err = decodeDate(raw, key)
		case 6:
			c.IssuedAt, err = decodeDate(raw, key)
		case 7:
			if majorType(raw) != majorBytes {
				return nil, fmt.Errorf("%w: claim 7 (cti) is not a byte string", ErrMalformed)
			}
			err = decMode.Unmarshal(raw, &c.CWTID)
		default:
			if c.Other == nil {
				c.Other = map[int64][]byte{}
			}
			c.Other[key] = []byte(raw)
		}
		if err != nil {
			return nil, wrapMalformed(err)
		}
	}
	return c, nil
}

// claimKey converts a decoded map key to an integer claim key (decision 0008, rule 4).
func claimKey(k any) (int64, error) {
	switch v := k.(type) {
	case uint64:
		if v > math.MaxInt64 {
			return 0, fmt.Errorf("%w: claim key %d is out of range", ErrMalformed, v)
		}
		return int64(v), nil
	case int64:
		return v, nil
	case string:
		return 0, fmt.Errorf("%w: text claim key %q", ErrUnsupported, v)
	default:
		return 0, fmt.Errorf("%w: claim key of type %T", ErrMalformed, k)
	}
}

func decodeText(raw []byte, key int64, dst *string) error {
	if majorType(raw) != majorText {
		return fmt.Errorf("%w: claim %d is not a text string", ErrMalformed, key)
	}
	return decMode.Unmarshal(raw, dst)
}

// decodeDate accepts an integer or a floating-point NumericDate (RFC 8392 Section 2, decision 0016).
func decodeDate(raw []byte, key int64) (*NumericDate, error) {
	switch {
	case isFloat(raw):
		var f float64
		if err := decMode.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("%w: claim %d: %v", ErrMalformed, key, err)
		}
		d, err := NumericDateFromFloat(f)
		if err != nil {
			return nil, fmt.Errorf("claim %d: %w", key, err)
		}
		return d, nil
	case majorType(raw) != majorUnsigned && majorType(raw) != majorNegative:
		return nil, fmt.Errorf("%w: claim %d is not a date", ErrMalformed, key)
	}
	var v int64
	if err := decMode.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("%w: claim %d: %v", ErrMalformed, key, err)
	}
	return NewNumericDate(v), nil
}

// decodeAudience accepts a text string or an array of untagged text strings (RFC 8392 Section 3.1.3).
func decodeAudience(raw []byte) ([]string, error) {
	if majorType(raw) == majorText {
		var s string
		if err := decodeText(raw, 3, &s); err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
	var items []cbor.RawMessage
	if majorType(raw) != majorArray || decMode.Unmarshal(raw, &items) != nil {
		return nil, fmt.Errorf("%w: claim 3 (aud) is neither a text string nor an array of them", ErrMalformed)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		var s string
		if err := decodeText(item, 3, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// wrapMalformed leaves errors that already carry one of this package's sentinels alone, and marks any other
// decoding error as malformed input.
func wrapMalformed(err error) error {
	if isSentinel(err) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrMalformed, err)
}
