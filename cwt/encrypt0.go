package cwt

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// COSE_Encrypt0 (RFC 9052 Section 5.2; decision 0030).
const (
	tagEncrypt0    = 16
	labelIV        = 5
	labelPartialIV = 6
	gcmIVSize      = 12
)

// IsEncrypted reports whether a token looks like a COSE_Encrypt0: tagged 16, through a CWT tag or not, or an
// untagged array of three elements. It does not check that the message is well formed; DecryptMessage does.
func IsEncrypted(token []byte) bool {
	if t := coseTagOf(token); t != 0 {
		return t == tagEncrypt0
	}
	var parts []cbor.RawMessage
	return len(token) > 0 && majorType(token) == majorArray && decMode.Unmarshal(token, &parts) == nil && len(parts) == 3
}

// DecryptMessage decrypts a COSE_Encrypt0 message, tagged or not, with the key that lookup returns for its kid, and
// returns its plaintext as the Message's Payload without interpreting it.
//
// The key decides the algorithm, which must be A128GCM, A192GCM or A256GCM, and an alg header, if present, must be
// protected and name the key's algorithm (decision 0015). The IV header must be present and 12 bytes long. A
// Partial IV, external data and any other header are not supported. A failed decryption is ErrVerification, since
// AES-GCM authenticates the message as it decrypts it.
func DecryptMessage(token []byte, lookup KeyLookup) (*Message, error) {
	if lookup == nil {
		return nil, errors.New("cwt: DecryptMessage needs a key lookup")
	}
	body := token
	if t := coseTagOf(token); t != 0 {
		if t != tagEncrypt0 {
			return nil, malformed("COSE tag %d is not COSE_Encrypt0", t)
		}
		var rt cbor.RawTag
		if err := decMode.Unmarshal(body, &rt); err != nil {
			return nil, malformed("tag: %v", err)
		}
		if rt.Number == tagCWT {
			if err := decMode.Unmarshal(rt.Content, &rt); err != nil {
				return nil, malformed("tag: %v", err)
			}
		}
		body = rt.Content
	} else if len(token) > 0 && majorType(token) == majorTag {
		return nil, malformed("token: unreadable tag")
	}
	var parts []cbor.RawMessage
	if err := decMode.Unmarshal(body, &parts); err != nil {
		return nil, malformed("not a COSE array: %v", err)
	}
	if len(parts) != 3 {
		return nil, malformed("COSE_Encrypt0 array has %d elements, want 3", len(parts))
	}
	for i, p := range parts {
		if len(p) == 0 {
			return nil, malformed("COSE element %d is empty", i)
		}
	}
	var protectedRaw []byte
	protected, unprotected, err := headersOf(parts[0], parts[1], &protectedRaw)
	if err != nil {
		return nil, err
	}
	alg, hasAlg, kid, iv, err := checkEncrypt0Headers(protected, unprotected)
	if err != nil {
		return nil, err
	}
	switch {
	case parts[2][0] == 0xf6:
		return nil, unsupported("detached ciphertext")
	case majorType(parts[2]) != majorBytes:
		return nil, malformed("ciphertext is not a byte string")
	}
	var ciphertext []byte
	if err := decMode.Unmarshal(parts[2], &ciphertext); err != nil {
		return nil, malformed("ciphertext: %v", err)
	}

	key, err := lookup(kid)
	if err != nil {
		return nil, fmt.Errorf("%w: key lookup: %w", ErrVerification, err)
	}
	size := key.Algorithm.aesGCMKeySize()
	if size == 0 {
		return nil, unverified("%v is not an encryption algorithm", key.Algorithm)
	}
	if hasAlg && alg != key.Algorithm {
		return nil, unverified("the token's alg is %v but its key is for %v", alg, key.Algorithm)
	}
	secret, ok := key.Material.([]byte)
	if !ok || len(secret) != size {
		return nil, unverified("%v needs a %d-byte key", key.Algorithm, size)
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, unverified("key: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, unverified("key: %v", err)
	}
	aad, err := cbor.Marshal([]any{"Encrypt0", nonNil(protectedRaw), []byte{}})
	if err != nil {
		return nil, malformed("building encryption structure: %v", err)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		return nil, ErrVerification
	}
	return &Message{Algorithm: key.Algorithm, KID: kid, Protected: protectedRaw, Payload: plaintext}, nil
}

// checkEncrypt0Headers applies decision 0008's header rules to a COSE_Encrypt0, with the IV header (5) allowed and
// required.
func checkEncrypt0Headers(protected, unprotected map[int64]cbor.RawMessage) (alg Algorithm, hasAlg bool, kid, iv []byte, err error) {
	var rawIV cbor.RawMessage
	for _, h := range []map[int64]cbor.RawMessage{protected, unprotected} {
		if _, ok := h[labelPartialIV]; ok {
			return 0, false, nil, nil, unsupported("a Partial IV")
		}
		if raw, ok := h[labelIV]; ok {
			if rawIV != nil {
				return 0, false, nil, nil, malformed("header parameter %d appears in both headers", labelIV)
			}
			rawIV = raw
		}
	}
	strip := func(h map[int64]cbor.RawMessage) map[int64]cbor.RawMessage {
		out := map[int64]cbor.RawMessage{}
		for k, v := range h {
			if k != labelIV {
				out[k] = v
			}
		}
		return out
	}
	if alg, hasAlg, kid, err = checkHeaders(strip(protected), strip(unprotected)); err != nil {
		return 0, false, nil, nil, err
	}
	if hasAlg && alg.aesGCMKeySize() == 0 {
		return 0, false, nil, nil, unsupported("%v for COSE_Encrypt0", alg)
	}
	if rawIV == nil {
		return 0, false, nil, nil, malformed("COSE_Encrypt0 has no IV")
	}
	if majorType(rawIV) != majorBytes || decMode.Unmarshal(rawIV, &iv) != nil {
		return 0, false, nil, nil, malformed("the IV is not a byte string")
	}
	if len(iv) != gcmIVSize {
		return 0, false, nil, nil, malformed("the IV is %d bytes; AES-GCM needs %d", len(iv), gcmIVSize)
	}
	return alg, hasAlg, kid, iv, nil
}
