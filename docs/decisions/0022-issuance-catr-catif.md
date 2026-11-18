# 0022. Issuing tokens, for `catr` and `catif`

- **Status:** accepted, 2026-11-15
- **Decided by:** Claude, under Terra Howard's delegation; pending her review. She may reverse it.
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

## Question asked

`catr` (section 4.9.2) renews an acceptable token, and `catif` (section 4.9.1) shapes the response to a valid but
unacceptable one, including tokens minted into its header values. Both need the recipient to sign new CATs. What
would an expert build, and how far?

## Reasoning

- **Issuing is a capability the operator opts into.** A recipient that signs tokens holds signing keys, and which
  keys, trusted by whom, is outside the specification (section 4.9.2). So issuance is off unless the `Validator`
  is given an `Issuance`: the issuer name to write into `iss`, and a function returning a signing key by `kid`.
  Without it, `catr` is ignored and `catif` minting yields empty strings, both of which the specification allows.
- **Keep layers where they are.** `cwt` learns to issue COSE_Mac0 and COSE_Sign1 tokens, the mirror of
  `VerifyMessage`. `cat` decides what to issue: renewal tokens and `catif` responses, as values the caller can
  inspect. `cathttp` applies them to HTTP responses, because only it knows where the token was found, which
  automatic renewal depends on.
- **Renew by changing only what section 4.9.2 changes.** The renewed token keeps the received claim set's
  encoding for every claim except `exp`, `iss`, `iat` and `cti`, so claims this package does not understand pass
  through untouched, as the section requires.
- **Build in the order that delivers value soonest and risks least:** issuance, then `catr`, then `catif`, whose
  substitutions and minted tokens are the most intricate part of the specification.

## Decision

1. **`cwt.Issue(payload, key)`** returns a tagged COSE_Mac0 (HMAC 256/256) or COSE_Sign1 (ES256, PS256) with `alg`
   in the protected header and the key's `kid`, if any, unprotected, deterministically encoded. Its tokens must
   verify with `VerifyMessage` and pass `cat`'s deterministic-encoding check.
2. **`cat.Issuance`** holds `Issuer` (written into `iss`) and `Key(kid string) (cwt.SigningKey, error)`; `kid`
   "" asks for the default renewal key. `Validator.Issuance` nil turns issuing off.
3. **`catr` (323):** decoded and checked for shape: `type` (0) and `expadd` (1) required; `deadline` (2), cookie
   name (3) and parameters (5), header name (4) and parameters (6), redirect status (7) optional; parameters not
   appropriate to the type mean no renewal (section 4.9.2); an unknown type is ignored. `Validator.Renew(token,
   now)` returns a `Renewal` (the new token's text, its type and parameters) or nothing: no `catr`, issuing off,
   before the deadline, or a deadline without `exp`. The new token has `exp` = now + `expadd`, `iss` = `Issuer`,
   `iat` = now, a fresh random 16-byte `cti` if and only if the old one had a `cti`, and every other claim as
   received. Cookie and header parameters are checked against RFC 6265 and RFC 9651 before use; if they cannot
   be added safely, there is no renewal.
4. **`cathttp`** applies a renewal after the handler: type 0 becomes cookie, header or redirect by where the token
   was found (section 4.9.2.1); cookie renewal sets the cookie, unless the handler already set one of that name;
   header renewal sets the field as an RFC 9651 list of one string, unless the handler already set it; redirect
   renewal answers with the status (default 307, 300 to 399 only) and the URI with the token replaced, and applies
   only to tokens found in the URI.
5. **`catif` (322)** follows, by the update below, once renewal is in place.
6. **Composition claims**, which section 4.3.1.5 mentions and other documents define, are not supported; a
   `catr` or `catif` is processed only in the base claim set.

## Update, 2026-11-15: `catif`

1. **Knowing why.** A refusal for an unacceptable claim becomes a `*cat.Unacceptable`, which carries the token and
   the key of the claim that refused it, and still unwraps to the same error (`cat.ErrExpired` and the rest), so
   existing `errors.Is` checks are unaffected. Invalid tokens never produce one, since section 4.9.1 forbids
   processing `catif` for them.
2. **`Validator.IfResponse(u, req, now)`** returns the status and header fields of the first `catif` member whose
   key is, or lists, the refusing claim, or nil. Header values that are arrays are built as section 4.9.1 says:
   strings as they are; 0 becomes the requested URI and 1 the URI with the token removed, both base64url; 2 a CBOR
   list of the refusing claim's key, base64url; other integers the empty string; and maps become CATs: `iss` null
   is filled with `Issuance.Issuer`, `iat` null with now, `catifdata` processed as the section describes, and the
   result signed with the key the action's `kid` names. Without `Issuance`, or if that key cannot be had, a map
   becomes the empty string, as the section allows. A `catif` that is malformed yields no response, never a
   different refusal.
3. **`cathttp`** answers a refused request with that response when there is one, and with 401 otherwise. Its
   header fields are set on a response that has none yet, so section 4.9.1's rule against overwriting is met.

