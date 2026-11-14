package cwt

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// CBOR tags (RFC 8392 Section 6; RFC 9052 Section 2).
const (
	tagCWT   = 61
	tagMac0  = 17
	tagSign1 = 18
)

// COSE header labels understood by version zero (decision 0008, rule 2).
const (
	labelAlg = 1
	labelKID = 4
)

// COSE algorithm identifiers (RFC 9053).
const (
	algHMAC256x64  = 4
	algHMAC256x256 = 5
	algES256       = -7
	algPS256       = -37
)

const majorMap = 5

// coseMessage is a parsed single-recipient COSE message (COSE_Mac0 or COSE_Sign1).
type coseMessage struct {
	protectedRaw []byte // the protected header exactly as received, for the MAC or signature structure
	alg          int64
	kid          []byte
	payload      []byte
	tag          []byte // the MAC tag or the signature
	coseTag      uint64 // the COSE tag found (17 or 18), or 0 for an untagged message
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformed}, args...)...)
}

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnsupported}, args...)...)
}

// parseCOSE parses a token that should be a COSE message with the given tag, applying decision 0008's rules for
// tags, structure and headers. A wantTag of 0 accepts either COSE_Mac0 or COSE_Sign1, tagged or not, and leaves
// the caller to match the tag to the algorithm (decision 0012). It does not verify anything.
func parseCOSE(token []byte, wantTag uint64) (*coseMessage, error) {
	var raw cbor.RawMessage
	if err := decMode.Unmarshal(token, &raw); err != nil {
		return nil, malformed("token: %v", err)
	}
	body := []byte(raw)
	var foundTag uint64
	if majorType(body) == majorTag {
		var rt cbor.RawTag
		if err := decMode.Unmarshal(body, &rt); err != nil {
			return nil, malformed("tag: %v", err)
		}
		if rt.Number == tagCWT {
			inner := []byte(rt.Content)
			if len(inner) == 0 || majorType(inner) != majorTag {
				return nil, malformed("a CWT tag must be followed by a COSE tag (RFC 8392 Section 6)")
			}
			if err := decMode.Unmarshal(inner, &rt); err != nil {
				return nil, malformed("tag: %v", err)
			}
		}
		switch {
		case wantTag != 0 && rt.Number != wantTag:
			return nil, malformed("COSE tag %d where %d was expected", rt.Number, wantTag)
		case wantTag == 0 && rt.Number != tagMac0 && rt.Number != tagSign1:
			return nil, malformed("COSE tag %d is neither COSE_Mac0 nor COSE_Sign1", rt.Number)
		}
		foundTag = rt.Number
		body = rt.Content
	}

	var parts []cbor.RawMessage
	if err := decMode.Unmarshal(body, &parts); err != nil {
		return nil, malformed("not a COSE array: %v", err)
	}
	if len(parts) != 4 {
		return nil, malformed("COSE array has %d elements, want 4", len(parts))
	}
	for i, p := range parts {
		if len(p) == 0 {
			return nil, malformed("COSE element %d is empty", i)
		}
	}

	msg := &coseMessage{coseTag: foundTag}
	if majorType(parts[0]) != majorBytes {
		return nil, malformed("protected header is not a byte string")
	}
	if err := decMode.Unmarshal(parts[0], &msg.protectedRaw); err != nil {
		return nil, malformed("protected header: %v", err)
	}
	protected, err := decodeHeader(msg.protectedRaw, true)
	if err != nil {
		return nil, err
	}
	if majorType(parts[1]) != majorMap {
		return nil, malformed("unprotected header is not a map")
	}
	unprotected, err := decodeHeader(parts[1], false)
	if err != nil {
		return nil, err
	}

	switch {
	case parts[2][0] == 0xf6: // CBOR null
		return nil, unsupported("detached payload")
	case majorType(parts[2]) != majorBytes:
		return nil, malformed("payload is not a byte string")
	}
	if err := decMode.Unmarshal(parts[2], &msg.payload); err != nil {
		return nil, malformed("payload: %v", err)
	}
	if majorType(parts[3]) != majorBytes {
		return nil, malformed("MAC tag or signature is not a byte string")
	}
	if err := decMode.Unmarshal(parts[3], &msg.tag); err != nil {
		return nil, malformed("MAC tag or signature: %v", err)
	}

	if msg.alg, msg.kid, err = checkHeaders(protected, unprotected); err != nil {
		return nil, err
	}
	return msg, nil
}

// decodeHeader decodes a header map. A zero-length protected header is an empty map (RFC 9052 Section 3).
func decodeHeader(data []byte, isProtected bool) (map[int64]cbor.RawMessage, error) {
	out := map[int64]cbor.RawMessage{}
	if isProtected && len(data) == 0 {
		return out, nil
	}
	var m map[any]cbor.RawMessage
	if err := decMode.Unmarshal(data, &m); err != nil {
		return nil, malformed("header: %v", err)
	}
	if m == nil {
		return nil, malformed("header is not a map")
	}
	for k, v := range m {
		switch label := k.(type) {
		case uint64:
			if label > 1<<62 {
				return nil, unsupported("header label %d", label)
			}
			out[int64(label)] = v
		case int64:
			out[label] = v
		case string:
			return nil, unsupported("text header label %q", label)
		default:
			return nil, malformed("header label of type %T", k)
		}
	}
	return out, nil
}

// checkHeaders applies decision 0008 rule 2 and returns the algorithm and key ID.
func checkHeaders(protected, unprotected map[int64]cbor.RawMessage) (alg int64, kid []byte, err error) {
	for _, h := range []map[int64]cbor.RawMessage{protected, unprotected} {
		for label := range h {
			if label != labelAlg && label != labelKID {
				return 0, nil, unsupported("header parameter %d is not understood", label)
			}
		}
	}
	for label := range protected {
		if _, both := unprotected[label]; both {
			return 0, nil, malformed("header parameter %d appears in both headers", label)
		}
	}
	if _, ok := unprotected[labelAlg]; ok {
		return 0, nil, malformed("alg must be in the protected header")
	}
	rawAlg, ok := protected[labelAlg]
	if !ok {
		return 0, nil, malformed("alg is missing")
	}
	switch majorType(rawAlg) {
	case majorUnsigned, majorNegative:
		if err := decMode.Unmarshal(rawAlg, &alg); err != nil {
			return 0, nil, malformed("alg: %v", err)
		}
	case majorText:
		return 0, nil, unsupported("text-string algorithm")
	default:
		return 0, nil, malformed("alg is neither an integer nor a text string")
	}
	if rawKID, ok := protected[labelKID]; ok {
		kid, err = decodeKID(rawKID)
	} else if rawKID, ok := unprotected[labelKID]; ok {
		kid, err = decodeKID(rawKID)
	}
	return alg, kid, err
}

func decodeKID(raw cbor.RawMessage) ([]byte, error) {
	if majorType(raw) != majorBytes {
		return nil, malformed("kid is not a byte string")
	}
	var kid []byte
	if err := decMode.Unmarshal(raw, &kid); err != nil {
		return nil, malformed("kid: %v", err)
	}
	return kid, nil
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// claimsFromPayload decodes a verified payload as a claims set, refusing nested CWTs (decision 0008, rule 3).
func claimsFromPayload(payload []byte) (*Claims, error) {
	if len(payload) > 0 && majorType(payload) == majorTag {
		return nil, unsupported("nested CWT")
	}
	return DecodeClaims(payload)
}
