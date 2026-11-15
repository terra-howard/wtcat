# How to validate a Common Access Token

This guide shows how to check a CAT with package `cat`. It assumes you have the token as text, as it arrives in a
request, and know your issuers' keys. A runnable version is `ExampleValidator` in
[cat/example_test.go](../../cat/example_test.go); `go test ./cat` checks that its output is still correct.

Finding the token in a request (path, query, cookie, header) is not part of this package yet.

## 1. Describe your keys

Each key is bound to one algorithm and one issuer:

```go
keys := map[string]cat.Key{
	"k1": {Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: secret}, Issuer: "issuer.example"},
	"k2": {Key: cwt.Key{Algorithm: cwt.ES256, Material: ecdsaPublicKey}, Issuer: "issuer.example"},
}
```

- `Material` is a `[]byte` for HMAC, an `*ecdsa.PublicKey` on P-256 for ES256, or an `*rsa.PublicKey` of at least
  2048 bits for PS256.
- The token never chooses the algorithm. If it has an `alg` header, the header must name the key's algorithm; if
  it has none, which CTA-5007-B allows, the key's algorithm is used.
- A token whose `iss` differs from the key's `Issuer` is refused. Leave `Issuer` empty only for a key that belongs
  to no issuer; then any token with an `iss` is refused.

## 2. Build a `Validator` once

```go
v := &cat.Validator{
	Keys: func(kid []byte) (cat.Key, error) {
		k, ok := keys[string(kid)]
		if !ok {
			return cat.Key{}, fmt.Errorf("no key for kid %x", kid)
		}
		return k, nil
	},
	Audiences: []string{"cdn.example"}, // the names this recipient answers to
}
```

- `kid` is nil when the token has none. Returning an error for nil refuses such tokens, which CTA-5007-B allows.
- A token with an `aud` claim must name one of `Audiences`.
- Leave `Now` unset in production; it defaults to `time.Now`. There is no leeway setting: CTA-5007-B forbids
  leeway on `exp` and `nbf`, so issuers build any margin into the claims themselves.
- `MaxLength` defaults to 8192 bytes of token text. It cannot be set below 4096, the size CTA-5007-B requires
  recipients to accept.

## 3. Validate, and branch on the kind of failure

```go
tok, err := v.Validate(text)
switch {
case err == nil:
	// Valid and acceptable: serve the request. tok.Claims holds the decoded claims.
case errors.Is(err, cat.ErrUnacceptable):
	// Valid, but a claim is not satisfied: cat.ErrExpired, cat.ErrNotYetValid, cat.ErrIssuer or cat.ErrAudience.
case errors.Is(err, cwt.ErrUnsupported):
	// Too long, or uses something this version does not handle, such as a claim it cannot enforce yet.
default:
	// cwt.ErrMalformed or cwt.ErrVerification: not a valid token.
}
```

CTA-5007-B separates *valid* tokens from *acceptable* ones, and a later version of this package will act on the
`catif` claim only for tokens that are valid but unacceptable. Keep that distinction in your handling now.

## What this version enforces

The package documentation (`go doc ./cat`) lists exactly which claims are enforced, which are refused because
they cannot be enforced yet, and which are ignored. A token restricted by `catu`, `catm`, `cath`, `catnip`, `cnf`
or `catdpop` is refused as unsupported rather than accepted with the restriction ignored.
