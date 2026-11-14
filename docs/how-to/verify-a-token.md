# How to verify a token

This guide shows how to check a CBOR Web Token with package `cwt`. It assumes you already have the token's bytes
and know which keys and algorithms your issuer uses. A runnable version is `ExampleVerifier` in
[cwt/example_test.go](../../cwt/example_test.go); `go test ./cwt` checks that its output is still correct.

## 1. Build a `Verifier` once

```go
v := &cwt.Verifier{
	Algorithms:    []cwt.Algorithm{cwt.HMAC256x256}, // only what your issuer uses
	Key:           lookupKey,                        // see step 2
	Leeway:        30 * time.Second,                 // allowance for clock skew
	RequireExpiry: true,                             // reject tokens that never expire
}
```

- List only the algorithms your issuer actually uses. A token with any other algorithm is rejected before your
  key lookup runs.
- Leave `Now` unset in production; it defaults to `time.Now`. Set it in tests to fix the clock.
- RFC 7519, whose time rules CWTs inherit, suggests leeway of "no more than a few minutes".

## 2. Write the key lookup

```go
func lookupKey(kid []byte, alg cwt.Algorithm) (any, error) {
	switch alg {
	case cwt.HMAC256x64, cwt.HMAC256x256:
		return secrets[string(kid)], nil // a []byte
	case cwt.ES256:
		return ecdsaKeys[string(kid)], nil // an *ecdsa.PublicKey on P-256
	case cwt.PS256:
		return rsaKeys[string(kid)], nil // an *rsa.PublicKey of at least 2048 bits
	}
	return nil, fmt.Errorf("no key for kid %x", kid)
}
```

- Return the key type that matches the algorithm you are given. A key of the wrong type is rejected, so a public
  key can never be misused as an HMAC secret.
- `kid` is nil when the token has none.
- An error you return comes back from `Verify` wrapped in `cwt.ErrVerification`, and `errors.Is` still finds
  your own error inside it.

## 3. Verify and branch on the kind of failure

```go
claims, err := v.Verify(token)
switch {
case errors.Is(err, cwt.ErrExpired), errors.Is(err, cwt.ErrNotYetValid):
	// authentic, but outside its validity window
case errors.Is(err, cwt.ErrMissingExpiry):
	// authentic, but has no exp and RequireExpiry is set
case errors.Is(err, cwt.ErrVerification):
	// not authentic: bad MAC or signature, unknown key, or wrong key type
case errors.Is(err, cwt.ErrUnsupported):
	// well formed, but uses something this version does not handle
case errors.Is(err, cwt.ErrMalformed):
	// not a well-formed token
case err != nil:
	// a configuration problem in the Verifier itself
}
```

## 4. Read the claims

`claims.Issuer`, `Subject`, `Audience`, `Expiry`, `NotBefore`, `IssuedAt` and `CWTID` hold RFC 8392's registered
claims. Every other claim, including the Common Access Token's own, is in `claims.Other`, keyed by its number, as
raw CBOR. Package `cwt` does not interpret CAT claims; that comes later, once their rules can be established from
the specification ([decision 0002](../decisions/0002-spec-sources.md)).

## What `cwt` does not do yet

- CAT claim validation (`catu`, `catr` and the rest).
- Nested CWTs, detached payloads, external authenticated data, text-string claim keys, and floating-point dates.
  Each returns `ErrUnsupported` rather than being guessed at.
