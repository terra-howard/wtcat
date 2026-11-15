package cwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
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
	if err := verifySign1Message(msg, key); err != nil {
		return nil, err
	}
	return msg.payload, nil
}

// verifySign1Message checks a parsed COSE_Sign1 message's signature with a public key.
func verifySign1Message(msg *coseMessage, key crypto.PublicKey) error {
	toBeSigned, err := sigStructure(msg.protectedRaw, msg.payload)
	if err != nil {
		return malformed("building signature structure: %v", err)
	}
	switch msg.alg {
	case ES256:
		return verifyES256(key, toBeSigned, msg.tag)
	case PS256:
		return verifyPS256(key, toBeSigned, msg.tag)
	default:
		return unsupported("%v for COSE_Sign1", msg.alg)
	}
}

// verifyES256 checks an ECDSA P-256 SHA-256 signature in COSE's fixed-length r||s form (RFC 9053 Section 2.1).
func verifyES256(key crypto.PublicKey, toBeSigned, sig []byte) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return unverified("ES256 needs an *ecdsa.PublicKey, got %T", key)
	}
	if pub.Curve != elliptic.P256() {
		return unverified("ES256 needs a P-256 key")
	}
	if len(sig) != 64 {
		return unverified("ES256 signature is %d bytes, want 64", len(sig))
	}
	digest := sha256.Sum256(toBeSigned)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return ErrVerification
	}
	return nil
}

// verifyPS256 checks an RSASSA-PSS signature with SHA-256, MGF1 with SHA-256 and a 32-byte salt (RFC 8230
// Section 2), on a key of at least 2048 bits, which RFC 8230 requires.
func verifyPS256(key crypto.PublicKey, toBeSigned, sig []byte) error {
	pub, ok := key.(*rsa.PublicKey)
	if !ok || pub == nil || pub.N == nil {
		return unverified("PS256 needs an *rsa.PublicKey, got %T", key)
	}
	if pub.N.BitLen() < 2048 {
		return unverified("PS256 key is %d bits; RFC 8230 requires at least 2048", pub.N.BitLen())
	}
	digest := sha256.Sum256(toBeSigned)
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, opts); err != nil {
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
