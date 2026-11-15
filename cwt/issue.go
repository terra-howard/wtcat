package cwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// SigningKey is a key for issuing tokens, bound to one algorithm (decision 0022).
type SigningKey struct {
	Algorithm Algorithm // HMAC256x256, ES256 or PS256
	KID       []byte    // written to the unprotected header when not nil
	// Material is a []byte secret for HMAC256x256, an *ecdsa.PrivateKey on P-256 for ES256, or an *rsa.PrivateKey
	// of at least 2048 bits for PS256.
	Material any
}

// Issue MACs or signs a payload as a tagged COSE_Mac0 (HMAC 256/256) or COSE_Sign1 (ES256, PS256) message, with
// alg alone in the protected header and the key's kid, if any, in the unprotected one. The encoding uses the
// shortest forms and definite lengths throughout.
func Issue(payload []byte, key SigningKey) ([]byte, error) {
	protected, err := cbor.Marshal(map[int64]int64{labelAlg: int64(key.Algorithm)})
	if err != nil {
		return nil, err
	}
	unprotected := map[int64]any{}
	if key.KID != nil {
		unprotected[labelKID] = key.KID
	}
	var tag uint64
	var proof []byte
	switch key.Algorithm {
	case HMAC256x256:
		secret, ok := key.Material.([]byte)
		if !ok || len(secret) == 0 {
			return nil, errors.New("cwt: HMAC 256/256 needs a non-empty []byte secret")
		}
		toMac, err := macStructure(protected, payload)
		if err != nil {
			return nil, err
		}
		h := hmac.New(sha256.New, secret)
		h.Write(toMac)
		tag, proof = tagMac0, h.Sum(nil)
	case ES256, PS256:
		toBeSigned, err := sigStructure(protected, payload)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(toBeSigned)
		if proof, err = sign(key, digest[:]); err != nil {
			return nil, err
		}
		tag = tagSign1
	default:
		return nil, fmt.Errorf("%w: issuing with algorithm %d", ErrUnsupported, key.Algorithm)
	}
	return cbor.Marshal(cbor.Tag{Number: tag, Content: []any{protected, unprotected, nonNil(payload), proof}})
}

// sign makes an ES256 signature in COSE's fixed-length r||s form, or a PS256 signature with a 32-byte salt.
func sign(key SigningKey, digest []byte) ([]byte, error) {
	switch k := key.Material.(type) {
	case *ecdsa.PrivateKey:
		if key.Algorithm != ES256 || k == nil || k.Curve != elliptic.P256() {
			return nil, errors.New("cwt: ES256 needs an *ecdsa.PrivateKey on P-256")
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return nil, err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	case *rsa.PrivateKey:
		if key.Algorithm != PS256 || k == nil || k.N == nil || k.N.BitLen() < 2048 {
			return nil, errors.New("cwt: PS256 needs an *rsa.PrivateKey of at least 2048 bits")
		}
		return rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	default:
		return nil, fmt.Errorf("cwt: algorithm %d cannot sign with a %T", key.Algorithm, key.Material)
	}
}
