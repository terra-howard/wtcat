# 0015. Reconciling `cwt` with CTA-5007-B, and the shape of a `cat` package

- **Status:** proposed, 2026-11-14
- **Decision needed from:** Terra Howard

## Context

Decisions 0006, 0008, 0010 and 0012 were made from RFC 8392 and public sources alone. The specification now
available differs from them in places. Section references below are to CTA-5007-B; the requirements are
paraphrased.

## Where the specification and `cwt` disagree

| Topic | CTA-5007-B | `cwt` today | Proposal |
|---|---|---|---|
| `alg` in the header | optional (4.3.1.1.1) | required, protected | Allow it to be absent only when the caller's key lookup supplies the algorithm; still refuse an `alg` in the unprotected header (decision 0009's reasoning stands) |
| Deterministic CBOR | required apart from map order; recipients should check (4.5) | indefinite lengths allowed, shortest forms not checked | `cat` rejects indefinite lengths and non-shortest encodings; `cwt` stays lenient for general CWTs |
| Floating-point dates | allowed for `exp`, `nbf`, `iat`; NaN and negative zero invalid (4.5, claims table) | refused as unsupported | Support finite floats in `cwt`, with an API change to the date fields |
| `aud` | a string or an array of strings | one string | Change `Claims.Audience` to a list |
| Leeway on `exp` and `nbf` | forbidden (4.6.3, 4.6.4) | `Verifier.Leeway` | `cwt` keeps leeway for general CWTs; `cat` always checks with none |
| Tags on claim values | forbidden on CAT's claims and their subvalues except `catnip` (4.5) | kept raw for unregistered claims | `cat` enforces it per claim |

Points where `cwt` already agrees: unknown claims are ignored (4.3.1.5); HMAC 256/256, PS256 and ES256 are
supported (4.3.1.1.1); a missing `kid` is allowed, and a `RequireKID` option would cover recipients that refuse it.

## A `cat` package, in phases

1. **Envelope and core claims:** base64url decoding with or without padding (4.3.1.1); a 4096-byte minimum supported
   size; the deterministic-encoding and tag rules; `catv` (must be 1); `iss`, `aud`, `exp`, `nbf` with no leeway,
   `cti`, `sub`, `iat`.
2. **Request claims,** checked against a request description the caller fills in: `catm`, `cath`, `catnip`, and
   `catu`. `catu` is the largest single piece: token removal, URI normalisation per RFC 9110 and RFC 3986, and
   POSIX extended regular expressions under resource limits.
3. **Proof of possession:** `cnf` with the `jkt` method and `catdpop`, which means verifying RFC 9449 DPoP proofs.
4. **Optional claims** (`catreplay`, `catalpn`, the geographic claims, `catr`, `catif` and the rest), each by its own
   decision.

HTTP-layer duties (where tokens are found, `Cache-Control: private`, removing tokens before forwarding) belong to a
separate integration package, not the validator.

## A finding that limits the outside vectors

The specification's ES256 example key (Annex B.1) is a secp256k1 key, not P-256, and its ES256 example tokens do
not verify with that key on either curve. Its HMAC 256/256 and PS256 examples do verify against `cwt`. ES256 keeps
relying on RFC 8392 and the COSE working group's vectors.
