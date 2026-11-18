package cat

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
)

// The keys draft-ietf-moq-c4m's test vectors use for its claims, which IANA has not yet assigned: private-use keys
// (RFC 8392 section 9.1) standing in for them (decision 0035).
const (
	DefaultMOQTClaimKey = -65537 // moqt
	DefaultMOQTRevalKey = -65538 // moqt-reval
)

// MOQT action codes from draft-ietf-moq-c4m's moqt claim.
const (
	MOQTSetup              = 1
	MOQTPublishNamespace   = 2
	MOQTSubscribeNamespace = 3
	MOQTSubscribe          = 4
	MOQTRequestUpdate      = 5
	MOQTPublish            = 6
	MOQTFetch              = 7
	MOQTTrackStatus        = 8
	MOQTSubscribeTracks    = 9
)

// MOQTAction is a MOQT action a token is presented for: the action code, the Track Namespace fields and the Track
// Name, as the MOQT message carries them (decision 0035). Track is nil for an action that names no track.
type MOQTAction struct {
	Action    int
	Namespace [][]byte
	Track     []byte
}

var (
	// ErrMOQT means the token's moqt claim does not authorize the MOQT action, or the token has no moqt claim.
	ErrMOQT = fmt.Errorf("%w: the moqt claim does not authorize this MOQT action", ErrUnacceptable)
	// ErrMOQTUnknownKey means the moqt claim holds a key this version does not know, which draft-ietf-moq-c4m says
	// makes the claim set unacceptable, so that a new restriction cannot be skipped.
	ErrMOQTUnknownKey = fmt.Errorf("%w: the moqt claim holds a key this version does not know", ErrUnacceptable)
)

// moqtScope is one scope of a moqt claim.
type moqtScope struct {
	actions   []int64
	namespace []binMatch // nil when the scope has no namespace matches
	track     *binMatch  // nil when the scope has no track match
}

// binMatch is an exact, prefix or suffix match on bytes, or the nil terminator of a namespace match list.
type binMatch struct {
	kind  int // 0 exact, 1 prefix, 2 suffix, -1 the nil terminator
	value []byte
}

func (m binMatch) matches(b []byte) bool {
	switch m.kind {
	case 1:
		return bytes.HasPrefix(b, m.value)
	case 2:
		return bytes.HasSuffix(b, m.value)
	}
	return bytes.Equal(b, m.value)
}

// decodeMOQT decodes a moqt claim under decision 0035. It returns the scopes, and whether the claim holds a key other
// than 0, which makes the claim set unacceptable but is not malformed.
func decodeMOQT(value cbor.RawMessage) ([]moqtScope, bool, error) {
	if majorType(value) != majorMap {
		return nil, false, malformed("the moqt claim is not a map")
	}
	var m map[any]cbor.RawMessage
	if err := decMode.Unmarshal(value, &m); err != nil {
		return nil, false, malformed("the moqt claim: %v", err)
	}
	unknown := false
	var scopesRaw cbor.RawMessage
	for k, v := range m {
		switch key := k.(type) {
		case uint64:
			if key == 0 {
				scopesRaw = v
			} else {
				unknown = true
			}
		case int64:
			unknown = true
		default:
			return nil, false, malformed("the moqt claim has a key of type %T", k)
		}
	}
	if scopesRaw == nil {
		return nil, false, malformed("the moqt claim has no scopes (key 0)")
	}
	items, err := array(scopesRaw, "the moqt claim's scopes")
	if err != nil {
		return nil, false, err
	}
	if len(items) == 0 {
		return nil, false, malformed("the moqt claim has no scopes")
	}
	scopes := make([]moqtScope, 0, len(items))
	for _, item := range items {
		s, err := decodeScope(item)
		if err != nil {
			return nil, false, err
		}
		scopes = append(scopes, s)
	}
	return scopes, unknown, nil
}

func decodeScope(raw cbor.RawMessage) (moqtScope, error) {
	var s moqtScope
	parts, err := array(raw, "a moqt scope")
	if err != nil {
		return s, err
	}
	if len(parts) < 1 || len(parts) > 3 {
		return s, malformed("a moqt scope has %d elements, want 1 to 3", len(parts))
	}
	actions, err := array(parts[0], "a moqt scope's actions")
	if err != nil {
		return s, err
	}
	if len(actions) == 0 {
		return s, malformed("a moqt scope has no actions")
	}
	for _, a := range actions {
		var n int64 // decoding into an integer refuses any other type
		if err := decMode.Unmarshal(a, &n); err != nil {
			return s, malformed("a moqt action is not an integer: %v", err)
		}
		s.actions = append(s.actions, n)
	}
	if len(parts) >= 2 {
		fields, err := array(parts[1], "a moqt scope's namespace matches")
		if err != nil {
			return s, err
		}
		if len(fields) == 0 {
			return s, malformed("a moqt scope has an empty list of namespace matches")
		}
		for i, f := range fields {
			m := binMatch{kind: -1}
			if len(f) == 1 && f[0] == cborNull {
				if i != len(fields)-1 {
					return s, malformed("nil is not the last of a moqt scope's namespace matches")
				}
			} else if m, err = decodeBinMatch(f); err != nil {
				return s, err
			}
			s.namespace = append(s.namespace, m)
		}
	}
	if len(parts) == 3 {
		m, err := decodeBinMatch(parts[2])
		if err != nil {
			return s, err
		}
		s.track = &m
	}
	return s, nil
}

// decodeBinMatch decodes a byte string (an exact match) or [1 or 2, byte string] (a prefix or suffix match).
func decodeBinMatch(raw cbor.RawMessage) (binMatch, error) {
	switch majorType(raw) {
	case majorBytes:
		var b []byte
		if err := decMode.Unmarshal(raw, &b); err != nil {
			return binMatch{}, malformed("a moqt match: %v", err)
		}
		return binMatch{value: b}, nil
	case majorArray:
		parts, err := array(raw, "a moqt match")
		if err != nil {
			return binMatch{}, err
		}
		if len(parts) != 2 || majorType(parts[0]) != majorUnsigned || majorType(parts[1]) != majorBytes {
			return binMatch{}, malformed("a moqt match is not [match type, byte string]")
		}
		var kind uint64
		var b []byte
		if decMode.Unmarshal(parts[0], &kind) != nil || decMode.Unmarshal(parts[1], &b) != nil {
			return binMatch{}, malformed("a moqt match is not [match type, byte string]")
		}
		if kind != 1 && kind != 2 {
			return binMatch{}, malformed("moqt match type %d is neither 1 (prefix) nor 2 (suffix)", kind)
		}
		return binMatch{kind: int(kind), value: b}, nil
	}
	return binMatch{}, malformed("a moqt match is neither a byte string nor [match type, byte string]")
}

// array decodes a CBOR array into its items.
func array(raw cbor.RawMessage, what string) ([]cbor.RawMessage, error) {
	if len(raw) == 0 || majorType(raw) != majorArray {
		return nil, malformed("%s is not an array", what)
	}
	var items []cbor.RawMessage
	if err := decMode.Unmarshal(raw, &items); err != nil {
		return nil, malformed("%s: %v", what, err)
	}
	return items, nil
}

// authorizes reports whether a scope allows a MOQT action.
func (s moqtScope) authorizes(a *MOQTAction) bool {
	if !slices.Contains(s.actions, int64(a.Action)) {
		return false
	}
	for i, m := range s.namespace {
		if m.kind == -1 {
			return len(a.Namespace) == i && s.trackAllows(a)
		}
		if i >= len(a.Namespace) || !m.matches(a.Namespace[i]) {
			return false
		}
	}
	return s.trackAllows(a)
}

func (s moqtScope) trackAllows(a *MOQTAction) bool {
	return s.track == nil || a.Track != nil && s.track.matches(a.Track)
}

// checkMOQT enforces the moqt claim for a MOQT request (decision 0035). A claim with an unknown key is unacceptable
// for any request. For a MOQT request, a token without the claim authorizes nothing.
func checkMOQT(c *Claims, req *Request) error {
	if c.moqtUnknownKey {
		return ErrMOQTUnknownKey
	}
	if req == nil || req.MOQT == nil {
		return nil
	}
	for _, s := range c.moqt { // a token without the claim has no scopes, so it authorizes nothing
		if s.authorizes(req.MOQT) {
			return nil
		}
	}
	return ErrMOQT
}
