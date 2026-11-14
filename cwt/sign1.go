package cwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// sigStructure builds RFC 9052 Section 4.4's Sig_structure for COSE_Sign1 with empty external data.
func sigStructure(protectedRaw, payload []byte) ([]byte, error) {
	return cbor.Marshal([]any{"Signature1", nonNil(protectedRaw), []byte{}, nonNil(payload)})
}

// verifySign1Payload verifies a COSE_Sign1 message and returns its payload, whatever the payload holds.
func verifySign1Payload(token []byte, key crypto.PublicKey) ([]byte, error) {
	msg, err := parseCOSE(token, tagSign1)
	if err != nil {
		return nil, err
	}
	toBeSigned, err := sigStructure(msg.protectedRaw, msg.payload)
	if err != nil {
		return nil, fmt.Errorf("building signature structure: %w", err)
	}
	switch msg.alg {
	case algES256:
		if err := verifyES256(key, toBeSigned, msg.tag); err != nil {
			return nil, err
		}
	case algPS256:
		return nil, unsupported("PS256 is deferred until it has an outside test vector (decision 0008, rule 7)")
	default:
		return nil, unsupported("algorithm %d for COSE_Sign1", msg.alg)
	}
	return msg.payload, nil
}

// verifyES256 checks an ECDSA P-256 SHA-256 signature in COSE's fixed-length r||s form (RFC 9053 Section 2.1).
func verifyES256(key crypto.PublicKey, toBeSigned, sig []byte) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("%w: ES256 needs an *ecdsa.PublicKey, got %T", ErrVerification, key)
	}
	if pub.Curve != elliptic.P256() {
		return fmt.Errorf("%w: ES256 needs a P-256 key", ErrVerification)
	}
	if len(sig) != 64 {
		return fmt.Errorf("%w: ES256 signature is %d bytes, want 64", ErrVerification, len(sig))
	}
	digest := sha256.Sum256(toBeSigned)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return ErrVerification
	}
	return nil
}

// VerifySign1 verifies a COSE_Sign1 CWT with a public key and returns its claims.
func VerifySign1(token []byte, key crypto.PublicKey) (*Claims, error) {
	payload, err := verifySign1Payload(token, key)
	if err != nil {
		return nil, err
	}
	return claimsFromPayload(payload)
}
