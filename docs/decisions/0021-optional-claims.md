# 0021. Phase 4: the optional claims

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation; pending her review. She may reverse it.

## Question asked

Every claim CTA-5007-B requires recipients to support is enforced. The rest are optional, and ignored today, which
the specification allows (section 4.5). Which should be enforced, how, and in what order?

## Reasoning

- **Enforce an optional claim only when the caller supplies what it needs.** Most of them compare the token with
  facts a validator cannot know: whether a `cti` was seen before, the client's country or position, the TLS ALPN or
  certificate. Each becomes enforceable through an optional field on `Validator` or `Request`. Without that field
  the claim stays ignored, never refused: refusing an optional claim the recipient cannot evaluate would deny tokens
  the specification says may be accepted.
- **Small, separable claims first; issuance last.** `catif` and `catr` do not restrict access. They shape the
  response to a refused token and renew tokens, and both make the recipient sign new CATs. That is a new capability
  with key-management questions (which keys a recipient may sign with, and how issuers learn of them), so it gets
  its own decision when it starts.

## Decision

1. **Order:** `catreplay`; the geographic claims (`catgeoiso3166`, `catgeocoord`, `geohash`, `catgeoalt`) with a
   client location the caller supplies; `catalpn` and `cattpk` with TLS facts the caller supplies; then `catif` and
   `catr`, after their own decision on token issuance. `catpor` and `catifdata` stay ignored.
2. **`catreplay` (308):** an untagged unsigned integer. `Validator.Replay`, if set, is called with a token's `cti`
   only after every other check has passed, so a refused token never uses up its `cti`. It records the `cti` and
   reports whether it had been seen. Value 0 never refuses (section 4.6.6 forbids it) and does not call `Replay`.
   Values 1 and 2 refuse a token that `Replay` reports as seen (`cat.ErrReplay`); for 2, `Replay` is the
   implementation-defined reuse detection section 4.6.6 leaves open. Values above 2 are undefined there and are
   treated as 1, the safer reading. Without `Replay`, or without a `cti`, nothing is refused.

## Consequences

- The `Replay` function decides how long to remember a `cti`; remembering it until the token's `exp` is enough.
- Until the issuance decision, tokens with `catif` or `catr` are accepted or refused on their other claims only,
  which section 4.5 permits.

## Update, 2026-11-14: the geographic claims, after reading sections 4.6.14 to 4.6.17

- **`catgeoiso3166` (316)** is enforced when the caller supplies `Request.Location`; a nil `Location` means the
  recipient does not locate clients, and the claim is ignored. A `Location` whose `Country` is empty means the
  client could not be located, and the token is refused (`cat.ErrLocation`), since accepting it would let a failed
  lookup bypass the restriction. Each entry must be an ISO 3166 country code, optionally followed by a dash and a
  region code; this package checks that syntax but holds no copy of ISO's lists, so a well-formed code that does not
  exist is not called invalid, as section 4.6.14 asks, but simply matches no client. That gap is recorded here.
- **`catgeocoord` (317)** must be carried in an encrypted claim (section 4.6.15), and this package does not decrypt
  tokens, so supporting it could only mean refusing it. It stays ignored, which section 4.5 permits.
- **`geohash` (282) and `catgeoalt` (318)** need the client's coordinates and altitude, which few recipients have.
  They wait until a caller needs them.

