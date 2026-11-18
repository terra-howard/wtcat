package cwt

import "fmt"

// Algorithm is a COSE algorithm identifier (RFC 9053).
type Algorithm int64

// The algorithms this package verifies. HMAC algorithms mean COSE_Mac0; signature algorithms mean COSE_Sign1.
const (
	HMAC256x64  Algorithm = 4   // HMAC with SHA-256, the tag truncated to 64 bits
	HMAC256x256 Algorithm = 5   // HMAC with SHA-256
	ES256       Algorithm = -7  // ECDSA on P-256 with SHA-256
	PS256       Algorithm = -37 // RSASSA-PSS with SHA-256

	// Content encryption algorithms, for DecryptMessage only (decision 0030). VerifyMessage refuses keys for them.
	A128GCM Algorithm = 1 // AES-GCM with a 128-bit key and a 128-bit tag
	A192GCM Algorithm = 2 // AES-GCM with a 192-bit key and a 128-bit tag
	A256GCM Algorithm = 3 // AES-GCM with a 256-bit key and a 128-bit tag
)

// String returns the algorithm's name as RFC 9053 and RFC 8230 write it, or "algorithm" and its identifier.
func (a Algorithm) String() string {
	switch a {
	case HMAC256x64:
		return "HMAC 256/64"
	case HMAC256x256:
		return "HMAC 256/256"
	case ES256:
		return "ES256"
	case PS256:
		return "PS256"
	case A128GCM:
		return "A128GCM"
	case A192GCM:
		return "A192GCM"
	case A256GCM:
		return "A256GCM"
	}
	return fmt.Sprintf("algorithm %d", int64(a))
}

func (a Algorithm) isMAC() bool { return a == HMAC256x64 || a == HMAC256x256 }

func (a Algorithm) known() bool { return a.isMAC() || a == ES256 || a == PS256 }

// aesGCMKeySize returns the key size in bytes of an AES-GCM algorithm, or 0 for any other algorithm.
func (a Algorithm) aesGCMKeySize() int {
	switch a {
	case A128GCM:
		return 16
	case A192GCM:
		return 24
	case A256GCM:
		return 32
	}
	return 0
}

// checkTagAgrees applies decision 0012: a COSE tag, if present, must agree with the algorithm.
func checkTagAgrees(coseTag uint64, a Algorithm) error {
	if a.isMAC() && coseTag == tagSign1 || !a.isMAC() && coseTag == tagMac0 {
		return malformed("COSE tag %d does not match %v", coseTag, a)
	}
	return nil
}

// verifyWith checks a parsed message's MAC or signature as algorithm a, with key material of the type a needs. The
// caller has checked that a is known and agrees with the message's tag.
func verifyWith(msg *coseMessage, a Algorithm, material any) error {
	msg.alg = a
	if !a.isMAC() {
		return verifySign1Message(msg, material)
	}
	secret, ok := material.([]byte)
	if !ok {
		return unverified("%v needs a []byte key, got %T", a, material)
	}
	return verifyMac0Message(msg, secret)
}
