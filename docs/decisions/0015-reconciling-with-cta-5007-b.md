# 0015. Reconciling `cwt` with CTA-5007-B, and the shape of a `cat` package

- **Status:** accepted, 2026-11-14 (proposed the same day), with changes to the proposal described below
- **Decided by:** Claude, under Terra Howard's delegation; pending her review. She may reverse it.
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

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

## Question asked

What would an expert software engineer do with these six conflicts and the phased plan, given that the protected
tests fix part of `cwt`'s API?

## What changed while deciding

Three facts, found on rereading the sources, change the proposal above.

1. **Two of the conflicts are `cwt`'s own gaps against RFC 8392, not differences CAT introduces.** RFC 8392
   Section 3.1.3 allows `aud` to be an array, and Section 2 defines a NumericDate as a CBOR numeric date, which
   may be a floating-point number. So `cwt` rejecting an `aud` array as malformed is a defect, and decision 0006's
   single-string `Audience` was a mistake. Refusing floating-point dates as unsupported is honest but incomplete.
2. **The protected tests fix `Claims.Audience` as a string and the date fields as `*int64`.** Changing either type
   would stop them compiling, so the change the proposal describes cannot be made without editing protected
   tests. That is the owner's alone (decision 0003). It goes to her as decision 0016, proposed.
3. **`cat` needs a different claims decoder anyway.** CTA-5007-B says recipients must ignore claims they do not
   understand (4.3.1.5, 4.5), and a claim with a text-string key is one of those; `cwt` refuses text-string keys.
   CAT also requires deterministic encoding, per-claim tag rules, and knowing whether `iss` was present at all,
   which `cwt.Claims` cannot say.

## Reasoning

- **Do not route around the protected boundary, and do not wait on it either.** An expert who finds that the
  clean fix needs a protected change writes the proposal for the owner and builds what does not depend on the
  answer. `cat` decodes its own claim set from a verified payload, with the right shapes from the start, so its
  progress does not hang on decision 0016.
- **Bind each key to one algorithm.** When `alg` may be absent, the algorithm has to come from somewhere trusted.
  The safe source is the key: each key is configured with the one algorithm it may be used with, the practice
  RFC 8725 recommends for JSON Web Tokens and that COSE keys support with their own `alg` field. A token with an
  `alg` header must name the key's algorithm; a token without one is verified with it. Algorithm confusion
  becomes impossible because the token never chooses the algorithm on its own. This belongs in `cwt`, as a new
  lower-level function that returns the verified payload uninterpreted, because any CWT profile, not only CAT,
  can use it. The existing functions keep requiring `alg`, so nothing already promised changes.
- **Fail closed on what is required but not yet built.** A recipient must enforce `catu`, `catm`, `cath`,
  `catnip`, `cnf` and `catdpop` (4.5). If phase 1 ignored them as unknown, a token restricted to one URI would
  be accepted for every URI. Until each is enforced, a token carrying one is refused as unsupported. Optional
  claims are ignored, as the specification allows for claims a recipient does not support, and the README lists
  exactly which claims are enforced, as section 4.3.1.5 asks recipients to communicate.
- **Mirror the specification's own vocabulary in the errors.** CTA-5007-B distinguishes a valid token from an
  acceptable one (4.3.1.2), and `catif` (phase 4) acts only on tokens that are valid but unacceptable. Errors from
  `cat` say which: invalid tokens carry `cwt`'s existing kinds (`ErrMalformed`, `ErrVerification`,
  `ErrUnsupported`), and unacceptable ones wrap a new `cat.ErrUnacceptable`. Adding the two-step form that `catif`
  will need is then a new method, not a change to an old one.
- **Be exact about time, and refuse what cannot be represented.** With no leeway allowed, a fractional `exp` must
  be compared exactly, not rounded to whole seconds. A date outside the range of 64-bit seconds is refused as
  unsupported, and a NaN or infinite date as malformed. Refusing is the safe direction for every date claim.
- **Strict where strictness removes ambiguity.** Base64url decoding accepts padded and unpadded tokens, as it
  must, but rejects line breaks and other characters (Go's decoder skips line breaks by default) and non-zero
  trailing bits, so one token has exactly one text form.

## Decision

1. **`cwt` gains `VerifyMessage`,** which verifies a COSE_Mac0 or COSE_Sign1 message with a key bound to one
   algorithm and returns the algorithm, the `kid`, the raw protected header and the payload, uninterpreted. `alg`
   may be absent; if present it must be protected and must equal the key's algorithm. `VerifyMac0`,
   `VerifySign1` and `Verifier` are unchanged.
2. **`cat` phase 1** as proposed, with these specifics:
   - the token is text, at most `MaxLength` bytes (default 8192, a common limit for one HTTP header line; a value
     below the 4096-byte floor is a configuration error), base64url with or without correct padding, strictly
     decoded;
   - deterministic encoding (RFC 8949 Section 4.2.1, plus the first rule of 4.2.2 as section 4.5 requires, with map
     order exempt) is checked on the token, its protected header and its payload;
   - claims as above, with `iss` acceptable only if it equals the issuer configured with the key, `aud`
     acceptable only if it names one of the recipient's configured audiences, and `exp` and `nbf` checked with
     no leeway;
   - `catv` must be an untagged unsigned integer, and any value but 1 is unsupported;
   - required claims not yet enforced are refused as unsupported; optional claims are ignored.
3. **The `cwt.Claims` changes** (an `aud` list, floating-point dates) are not made here. They are decision 0016,
   for the owner, because they change protected tests.
4. **Known gaps, recorded so they are not mistaken for decisions:** COSE_Sign and COSE_Mac (more than one signer
   or recipient) and COSE_Encrypt0 are not supported, and `cwt` reports a COSE_Sign or COSE_Mac tag as malformed
   where unsupported would be more accurate. Encrypted tokens are optional for recipients (4.3.1.1.1). Multiple
   signers will need their own decision.
5. Phases 2 to 4 each get their own decision when they start.

## Consequences

- `cat` has its own claims type, so the core claims are decoded in two places until decision 0016 is settled.
- A phase 1 `cat` refuses the specification's own A.3 examples as unsupported, because they carry `catu`. That is
  correct for phase 1 and changes in phase 2.
