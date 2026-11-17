# Errors

Every error the packages return on purpose, what it means, and what usually causes it. Test for them with
`errors.Is`; the `cat.Unacceptable` type with `errors.As`. Errors not listed here are configuration errors, such as a
`Validator` with no key function, and wrap none of these.

## Invalid tokens

A token is *invalid* when it is not well formed, not authentic, or not of a shape this version can check (CTA-5007-B
section 4.3.1.2). Nothing it says is trusted, and no `catif` response is made for it.

| Error | Meaning | Usual causes |
|---|---|---|
| `cwt.ErrMalformed` | The token is not well formed | Not base64url, or not canonically encoded; CBOR not deterministically encoded; a claim of the wrong type or tagged; duplicate map keys; an RFC 9164 prefix in a non-canonical form, or more specific than an unencrypted `catnip` may be |
| `cwt.ErrVerification` | The MAC or signature does not verify with the key for its `kid` | The wrong key; a changed token; the key lookup failed (its own error is wrapped too); a key of the wrong type for the algorithm |
| `cwt.ErrUnsupported` | A valid construct this version does not handle | An algorithm not offered; a `catv` other than 1; a token longer than `MaxLength`; a claim with a request part given to `Validate` instead of `ValidateRequest`; a `cnf` method other than `jkt`; a `catu` component, match type or regular expression this version cannot check |

## Valid but unacceptable tokens

A token is *unacceptable* when it is valid but one of its claims is not satisfied. Each of these wraps
`cat.ErrUnacceptable`, and the error returned is a `*cat.Unacceptable` carrying the token and the key of the claim
that refused it, which `Validator.IfResponse` uses to answer as the token's `catif` asks.

| Error | Claim | Meaning |
|---|---|---|
| `cat.ErrUnacceptable` | any | Valid but not acceptable; every error below wraps it |
| `cat.ErrIssuer` | `iss` (1) | `iss` is not the issuer configured with the key that verified the token |
| `cat.ErrAudience` | `aud` (3) | `aud` names none of the `Validator`'s `Audiences` |
| `cat.ErrExpired` | `exp` (4) | The current time is at or after `exp`; there is no leeway |
| `cat.ErrNotYetValid` | `nbf` (5) | The current time is before `nbf`; there is no leeway |
| `cat.ErrProof` | `cnf` (8) | No single DPoP proof in the request was made with the key `cnf` names and matches the request, or a token in the DPoP scheme is not bound by `cnf` |
| `cat.ErrReplay` | `catreplay` (308) | `catreplay` forbids reuse, and `Validator.Replay` reports the `cti` was seen before |
| `cat.ErrNetwork` | `catnip` (311) | Neither the client's address nor its ASN is listed |
| `cat.ErrURI` | `catu` (312) | A component of the normalized request URI does not match, or the URI cannot be parsed |
| `cat.ErrMethod` | `catm` (313) | The request's method is not listed |
| `cat.ErrConnection` | `catalpn` (314), `cattpk` (319) | The request was not made over TLS, its ALPN is not listed, or no client certificate has the listed key |
| `cat.ErrHeader` | `cath` (315) | A named header is missing, or its value does not match |
| `cat.ErrLocation` | `catgeoiso3166` (316), `geohash` (282) | The client is not in a listed country, region or geohash cell, or could not be located |

## Other errors from `cwt`

| Error | Meaning |
|---|---|
| `cwt.ErrExpired` | From `cwt.Verifier` and `Claims.CheckTime`: the current time is at or after `exp`, after leeway |
| `cwt.ErrNotYetValid` | From the same: the current time is before `nbf`, after leeway |
| `cwt.ErrMissingExpiry` | `cwt.Verifier` with `RequireExpiry` set received a token without `exp` |

## Renewal

| Error | Meaning |
|---|---|
| `cat.ErrNoRenewal` | From `Validator.Renew`: the token's `catr` cannot be followed (malformed, a parameter inappropriate to its type, a deadline without `exp`, or no signing key). The token itself is unaffected. `Renew` returns no error, and no renewal, when there is simply nothing to do |

## `cathttp`

| Error | Meaning |
|---|---|
| `cathttp.ErrNoToken` | The request carries no token where the `Authorizer` looks. The middleware answers 401 and does not mark the response private |
| `cathttp.ErrField` | The `CTA-Common-Access-Token` field, or the configured one, is present but is not a single token or string. Section 4.4 then forbids looking elsewhere, so the request has no usable token |
