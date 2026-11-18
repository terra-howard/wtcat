# 0006. The first API: package `cwt`

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation for an experiment (see decision 0007). Pending her
  review; she may reverse it.
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

## Question asked

What would an expert software engineer do with this API, for a security-sensitive verifier at version zero?

## Reasoning

- **Algorithm confusion is the classic failure of token libraries.** JSON Web Token libraries have been broken by
  verifying an HMAC token with a public key read as an HMAC secret. Separate functions for MAC and signature
  verification, taking different key types, make that confusion impossible by construction. Within each function,
  the token's algorithm must agree with the key's type.
- **Pinning comes next, without breaking this.** An expert would expect a `Verifier` type with options (an
  allow-list of algorithms, key lookup by `kid`, a clock and allowed skew for validity checks). It can be added on
  top of these functions later. Version zero promises no stability, so starting small is right.
- **Separate authenticity from validity.** Mixing them makes both harder to test, and the RFC's examples expired
  in 2015.

## Accepted as proposed, with the expected next step recorded above.

## Context

The first protected tests (RFC 8392 Appendix A) need an API to call. That API is a choice with lasting cost, so it
is proposed here rather than settled by the tests that use it. CAT-specific claims come later, in a separate
package built on this one.

## Proposal

Package `github.com/terra-howard/wtcat/cwt`:

```go
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

func DecodeClaims(data []byte) (*Claims, error)                     // an unprotected CWT Claims Set
func VerifyMac0(token, key []byte) (*Claims, error)                 // a COSE_Mac0 CWT
func VerifySign1(token []byte, key crypto.PublicKey) (*Claims, error) // a COSE_Sign1 CWT

var ErrVerification error // the MAC or signature does not verify, including a tag of the wrong length
var ErrMalformed error    // the input is not a well-formed token of the expected structure
var ErrUnsupported error  // a valid construct this version does not handle
```

Rules:

- An optional CWT tag (61) is accepted. A COSE tag, if present, must match the function: 17 for `VerifyMac0`, 18
  for `VerifySign1`.
- The algorithm is read from the protected header and must agree with the key's type. First algorithms: HMAC
  256/64 (4) and HMAC 256/256 (5) for COSE_Mac0; ES256 (-7) and PS256 (-37) for COSE_Sign1. Anything else returns
  `ErrUnsupported`.
- MAC tags are compared with `hmac.Equal`.
- Verification checks authenticity only. Whether a token is within its validity period is a separate step, so the
  RFC's example tokens (which expired in 2015) still verify.
- RFC 8392 allows floating-point dates. This version returns `ErrUnsupported` for them instead of guessing a
  rounding rule. An RFC 8392 erratum (reported, not yet verified) proposes that such dates be finite, which a later
  version can enforce.

## Consequences

- Negative protected tests can require `ErrVerification` specifically, so a stub that returns some other error
  cannot pass them.
- Exposing raw CBOR in `Other` keeps the CBOR library out of the public API.
