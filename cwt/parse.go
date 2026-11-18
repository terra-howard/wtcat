package cwt

import (
	"fmt"
	"math"

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
	labelTyp = 16 // RFC 9596; decision 0033
)

// coseMessage is a parsed single-recipient COSE message (COSE_Mac0 or COSE_Sign1).
type coseMessage struct {
	protectedRaw []byte // the protected header exactly as received, for the MAC or signature structure
	alg          Algorithm
	hasAlg       bool // false when no alg header is present (allowed only by VerifyMessage)
	kid          []byte
	payload      []byte
	tag          []byte // the MAC tag or the signature
	coseTag      uint64 // the COSE tag found (17 or 18), or 0 for an untagged message
	typ          string // the typ header, as headerType formats it; empty when absent
}

// parseCOSE parses a token that should be a COSE message with the given tag, applying decision 0008's rules for
// tags, structure and headers. A wantTag of 0 accepts either COSE_Mac0 or COSE_Sign1, tagged or not, and leaves
// the caller to match the tag to the algorithm (decision 0012). It does not verify anything.
func parseCOSE(token []byte, wantTag uint64) (*coseMessage, error) {
	msg, err := parseMessage(token, wantTag)
	if err != nil {
		return nil, err
	}
	if !msg.hasAlg {
		return nil, malformed("alg is missing")
	}
	return msg, nil
}

// parseMessage is parseCOSE without the requirement that alg be present, for VerifyMessage (decision 0015), where
// the key supplies the algorithm.
func parseMessage(token []byte, wantTag uint64) (*coseMessage, error) {
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

	if msg.alg, msg.hasAlg, msg.kid, err = checkHeaders(protected, unprotected); err != nil {
		return nil, err
	}
	if msg.typ, err = headerType(protected, unprotected); err != nil {
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
			if label > math.MaxInt64 {
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

// checkHeaders applies decision 0008 rule 2 and returns the algorithm, whether one was present, and the key ID.
func checkHeaders(protected, unprotected map[int64]cbor.RawMessage) (alg Algorithm, hasAlg bool, kid []byte, err error) {
	for _, h := range []map[int64]cbor.RawMessage{protected, unprotected} {
		for label := range h {
			if label != labelAlg && label != labelKID && label != labelTyp {
				return 0, false, nil, unsupported("header parameter %d is not understood", label)
			}
		}
	}
	for label := range protected {
		if _, both := unprotected[label]; both {
			return 0, false, nil, malformed("header parameter %d appears in both headers", label)
		}
	}
	if _, ok := unprotected[labelAlg]; ok {
		return 0, false, nil, malformed("alg must be in the protected header")
	}
	if rawAlg, ok := protected[labelAlg]; ok {
		hasAlg = true
		switch majorType(rawAlg) {
		case majorUnsigned, majorNegative:
			var id int64
			if err := decMode.Unmarshal(rawAlg, &id); err != nil {
				return 0, false, nil, malformed("alg: %v", err)
			}
			alg = Algorithm(id)
		case majorText:
			return 0, false, nil, unsupported("text-string algorithm")
		default:
			return 0, false, nil, malformed("alg is neither an integer nor a text string")
		}
	}
	if rawKID, ok := protected[labelKID]; ok {
		kid, err = decodeKID(rawKID)
	} else if rawKID, ok := unprotected[labelKID]; ok {
		kid, err = decodeKID(rawKID)
	}
	return alg, hasAlg, kid, err
}

// headerType returns the typ header (RFC 9596) from whichever header holds it: a text string as it is, an unsigned
// integer (a CoAP content format) in decimal after "#", so that it can never equal a media type, and "" when there
// is none (decision 0033). checkHeaders has already refused a typ in both headers.
func headerType(protected, unprotected map[int64]cbor.RawMessage) (string, error) {
	raw, ok := protected[labelTyp]
	if !ok {
		if raw, ok = unprotected[labelTyp]; !ok {
			return "", nil
		}
	}
	switch majorType(raw) {
	case majorText:
		var s string
		if err := decMode.Unmarshal(raw, &s); err != nil {
			return "", malformed("typ: %v", err)
		}
		return s, nil
	case majorUnsigned:
		var n uint64
		if err := decMode.Unmarshal(raw, &n); err != nil {
			return "", malformed("typ: %v", err)
		}
		return fmt.Sprintf("#%d", n), nil
	}
	return "", malformed("typ is neither a text string nor an unsigned integer")
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

// claimsFromPayload decodes a verified payload as a claims set, refusing nested CWTs (decision 0008, rule 3).
func claimsFromPayload(payload []byte) (*Claims, error) {
	if len(payload) > 0 && majorType(payload) == majorTag {
		return nil, unsupported("nested CWT")
	}
	return DecodeClaims(payload)
}
