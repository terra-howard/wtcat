package cwt

import (
	"errors"
	"fmt"
)

// Key is a verification key bound to the one algorithm it may be used with (decision 0015).
type Key struct {
	Algorithm Algorithm
	// Material is a []byte secret for HMAC256x64 and HMAC256x256, an *ecdsa.PublicKey for ES256, or an
	// *rsa.PublicKey for PS256.
	Material any
}

// KeyLookup returns the key for a message's kid, which is nil when the message has none.
type KeyLookup func(kid []byte) (Key, error)

// Message is a COSE_Mac0 or COSE_Sign1 message whose MAC or signature verified.
type Message struct {
	Algorithm Algorithm // the key's algorithm, which any alg header matched
	KID       []byte    // nil when the message has no kid
	Protected []byte    // the protected header exactly as received: an encoded map, or empty
	Payload   []byte    // not interpreted
}

// VerifyMessage verifies a COSE_Mac0 or COSE_Sign1 message, tagged or not, with the key that lookup returns for
// its kid, and returns the message without interpreting its payload.
//
// The key's algorithm decides how the message is verified. An alg header is optional (CTA-5007-B section
// 4.3.1.1.1); if present it must be protected and must name the key's algorithm. Header rules are otherwise those
// of decision 0008. Unlike VerifyMac0, VerifySign1 and Verifier, the token never chooses the algorithm.
func VerifyMessage(token []byte, lookup KeyLookup) (*Message, error) {
	if lookup == nil {
		return nil, errors.New("cwt: VerifyMessage needs a key lookup")
	}
	msg, err := parseMessage(token, 0)
	if err != nil {
		return nil, err
	}
	if msg.hasAlg {
		if !msg.alg.known() {
			return nil, unsupported("%v", msg.alg)
		}
		if err := checkTagAgrees(msg.coseTag, msg.alg); err != nil {
			return nil, err
		}
	}

	key, err := lookup(msg.kid)
	if err != nil {
		return nil, fmt.Errorf("%w: key lookup: %w", ErrVerification, err)
	}
	if !key.Algorithm.known() {
		return nil, unsupported("key for %v", key.Algorithm)
	}
	if msg.hasAlg && msg.alg != key.Algorithm {
		return nil, unverified("the token's alg is %v but its key is for %v", msg.alg, key.Algorithm)
	}
	if err := checkTagAgrees(msg.coseTag, key.Algorithm); err != nil {
		return nil, err
	}
	if err := verifyWith(msg, key.Algorithm, key.Material); err != nil {
		return nil, err
	}
	return &Message{Algorithm: key.Algorithm, KID: msg.kid, Protected: msg.protectedRaw, Payload: msg.payload}, nil
}
