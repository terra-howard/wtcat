package cwt

import (
	"errors"
	"fmt"
)

// Claims holds the registered claims of RFC 8392 Section 3.1 and keeps every other claim as raw CBOR.
type Claims struct {
	Issuer    string           // claim 1, iss
	Subject   string           // claim 2, sub
	Audience  []string         // claim 3, aud: a single string becomes one element; nil when absent
	Expiry    *NumericDate     // claim 4, exp; nil when absent
	NotBefore *NumericDate     // claim 5, nbf
	IssuedAt  *NumericDate     // claim 6, iat
	CWTID     []byte           // claim 7, cti
	Other     map[int64][]byte // every other claim, by key, as its raw CBOR encoding
}

// The kinds of invalid token. Every error a verification or decoding function returns for a bad token wraps
// exactly one of them, so it can be tested with errors.Is.
var (
	// ErrVerification means the MAC or signature does not verify, including a tag of the wrong length.
	ErrVerification = errors.New("cwt: verification failed")
	// ErrMalformed means the input is not a well-formed token of the expected structure.
	ErrMalformed = errors.New("cwt: malformed token")
	// ErrUnsupported means a valid construct this version does not handle.
	ErrUnsupported = errors.New("cwt: unsupported")
)

func malformed(format string, args ...any) error { return kind(ErrMalformed, format, args) }

func unsupported(format string, args ...any) error { return kind(ErrUnsupported, format, args) }

func unverified(format string, args ...any) error { return kind(ErrVerification, format, args) }

func kind(sentinel error, format string, args []any) error {
	return fmt.Errorf("%w: "+format, append([]any{sentinel}, args...)...)
}

// isSentinel reports whether err already wraps one of the kinds above.
func isSentinel(err error) bool {
	return errors.Is(err, ErrVerification) || errors.Is(err, ErrMalformed) || errors.Is(err, ErrUnsupported)
}

// nonNil replaces a nil slice with an empty one, because the CBOR encoder writes a nil slice as null, not as an
// empty byte string.
func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
