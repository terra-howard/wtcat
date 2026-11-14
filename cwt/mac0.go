package cwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// macStructure builds RFC 9052 Section 6.3's MAC_structure for COSE_Mac0 with empty external data. Nil slices
// are replaced with empty ones, because the CBOR encoder writes a nil slice as null, not as an empty byte string.
func macStructure(protectedRaw, payload []byte) ([]byte, error) {
	return cbor.Marshal([]any{"MAC0", nonNil(protectedRaw), []byte{}, nonNil(payload)})
}

// verifyMac0Payload verifies a COSE_Mac0 message and returns its payload, whatever the payload holds.
func verifyMac0Payload(token, key []byte) ([]byte, error) {
	msg, err := parseCOSE(token, tagMac0)
	if err != nil {
		return nil, err
	}
	if err := verifyMac0Message(msg, key); err != nil {
		return nil, err
	}
	return msg.payload, nil
}

// verifyMac0Message checks a parsed COSE_Mac0 message's tag with a symmetric key.
func verifyMac0Message(msg *coseMessage, key []byte) error {
	var tagLen int
	switch msg.alg {
	case algHMAC256x64:
		tagLen = 8
	case algHMAC256x256:
		tagLen = 32
	default:
		return unsupported("algorithm %d for COSE_Mac0", msg.alg)
	}
	if len(key) == 0 {
		return fmt.Errorf("%w: empty key", ErrVerification)
	}
	toMac, err := macStructure(msg.protectedRaw, msg.payload)
	if err != nil {
		return fmt.Errorf("%w: building MAC structure: %v", ErrMalformed, err)
	}
	h := hmac.New(sha256.New, key)
	h.Write(toMac)
	want := h.Sum(nil)[:tagLen]
	if len(msg.tag) != tagLen || !hmac.Equal(msg.tag, want) {
		return ErrVerification
	}
	return nil
}

// VerifyMac0 verifies a COSE_Mac0 CWT with a symmetric key and returns its claims.
func VerifyMac0(token, key []byte) (*Claims, error) {
	payload, err := verifyMac0Payload(token, key)
	if err != nil {
		return nil, err
	}
	return claimsFromPayload(payload)
}
