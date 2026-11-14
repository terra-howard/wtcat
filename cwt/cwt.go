package cwt

import "errors"

// isSentinel reports whether err already wraps one of this package's sentinel errors.
func isSentinel(err error) bool {
	return errors.Is(err, ErrVerification) || errors.Is(err, ErrMalformed) || errors.Is(err, ErrUnsupported)
}

// Claims holds the registered claims of RFC 8392 Section 3.1 and keeps every other claim as raw CBOR.
type Claims struct {
	Issuer    string           // claim 1, iss
	Subject   string           // claim 2, sub
	Audience  string           // claim 3, aud
	Expiry    *int64           // claim 4, exp, seconds since the epoch; nil when absent
	NotBefore *int64           // claim 5, nbf
	IssuedAt  *int64           // claim 6, iat
	CWTID     []byte           // claim 7, cti
	Other     map[int64][]byte // every other claim, by key, as its raw CBOR encoding
}

var (
	// ErrVerification means the MAC or signature does not verify, including a tag of the wrong length.
	ErrVerification = errors.New("cwt: verification failed")
	// ErrMalformed means the input is not a well-formed token of the expected structure.
	ErrMalformed = errors.New("cwt: malformed token")
	// ErrUnsupported means a valid construct this version does not handle.
	ErrUnsupported = errors.New("cwt: unsupported")
)
