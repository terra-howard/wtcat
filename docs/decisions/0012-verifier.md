# 0012. The `Verifier`

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation for an experiment (see decision 0007). Pending her
  review; she may reverse it.

## Question asked

Decision 0006 recorded a `Verifier` as the expected next step. What shape would an expert give it?

## Reasoning

A CDN edge holds several keys at once (rotation), may accept more than one algorithm, and must reject tokens
outside their validity window. The functions from 0006 make the caller do all of that by hand, and hand-rolled
checks are where token libraries have historically gone wrong. Three points carry the design:

- **Allow-list first.** The token's algorithm is checked against an explicit list before any key is looked up, so
  a token claiming an algorithm the caller never meant to accept does not even reach key lookup. The list is
  required; there is no default, because a default is a decision the caller did not make.
- **The algorithm picks the structure.** HMAC algorithms mean COSE_Mac0 and signature algorithms mean COSE_Sign1.
  The algorithm sits in the protected header, so it is authenticated. A COSE tag, if present, must agree. That
  lets one `Verifier` handle tagged and untagged tokens of either kind without ever treating a signature key as an
  HMAC secret: the key lookup is told the algorithm, and the key's type must match it.
- **Time comes from the caller's clock**, with leeway and an option to require `exp`.

## Decision

```go
type Algorithm int64 // HMAC256x64 (4), HMAC256x256 (5), ES256 (-7), PS256 (-37)

// KeyFunc returns the key for a token's kid and algorithm: []byte for HMAC, a public key for signatures.
type KeyFunc func(kid []byte, alg Algorithm) (any, error)

type Verifier struct {
	Algorithms    []Algorithm      // required
	Key           KeyFunc          // required
	Now           func() time.Time // optional; time.Now when nil
	Leeway        time.Duration
	RequireExpiry bool
}

func (v *Verifier) Verify(token []byte) (*Claims, error)

var ErrMissingExpiry error // RequireExpiry is set and the token has no exp
```

- An algorithm outside `Algorithms` is `ErrUnsupported`, and `Key` is not called.
- A `Key` error is returned as `ErrVerification` wrapping the caller's error, so both can be tested with
  `errors.Is`.
- A `Verifier` with no algorithms or no key function returns a plain configuration error, never a token error.
- `VerifyMac0` and `VerifySign1` stay as the lower-level API.
