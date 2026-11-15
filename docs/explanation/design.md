# Why the validator is built the way it is

This page explains the design of packages `cwt`, `cat` and `cathttp`: what they promise, where they are strict, and
why. The reasoning was worked out one decision at a time, in [docs/decisions/](../decisions/); this page puts it in
one place. Each section names the decisions behind it, for the full argument.

Section numbers refer to CTA-5007-B, *Common Access Token*, which is free to download from the Consumer Technology
Association and is not reproduced here.

## Three layers, each with one job

- **`cwt`** knows CBOR Web Tokens and COSE: it verifies COSE_Mac0 and COSE_Sign1 messages, decodes the registered
  claims of RFC 8392, and issues tokens. It knows nothing about CAT.
- **`cat`** knows CTA-5007-B: which claims exist, what each requires, and whether a token is acceptable for a request
  described by a plain struct. It knows nothing about HTTP servers.
- **`cathttp`** knows HTTP: where tokens are found in a request, how to remove one from a URI, and how to answer,
  renew and forward.

The split keeps each layer testable on its own and usable alone: a recipient on an edge runtime can use `cat`
without `net/http`, and a CWT profile other than CAT can use `cwt`
([0006](../decisions/0006-cwt-package-api.md), [0015](../decisions/0015-reconciling-with-cta-5007-b.md),
[0019](../decisions/0019-http-integration.md)).

## Valid is not the same as acceptable

CTA-5007-B calls a token *valid* when it is well formed, authentic and syntactically correct, and *acceptable* when
every claim in it is satisfied (section 4.3.1.2). The packages keep that line visible in their errors:

- An invalid token is refused with one of `cwt`'s kinds: `ErrMalformed`, `ErrVerification` or `ErrUnsupported`.
- A valid but unacceptable token is refused with an error that wraps `cat.ErrUnacceptable`, and, as a
  `*cat.Unacceptable`, carries the token and the claim that refused it.

The distinction matters because the specification treats the two differently. Only a valid token's `catif` claim
may shape the response to a refusal (section 4.9.1); an invalid token is simply refused, since nothing it says can
be trusted ([0015](../decisions/0015-reconciling-with-cta-5007-b.md), [0022](../decisions/0022-issuance-catr-catif.md)).

## The token never chooses its own algorithm

Token libraries have repeatedly been broken by letting a token's header pick the algorithm used to check it, for
instance verifying an HMAC token with a public key read as a secret. Here, each key is configured with the one
algorithm it may be used with. A token that names an algorithm must name its key's; a token that names none, which
CTA-5007-B allows, is checked with the key's. So algorithm confusion has nowhere to start
([0006](../decisions/0006-cwt-package-api.md), [0015](../decisions/0015-reconciling-with-cta-5007-b.md)).

The same idea carries to DPoP proofs, whose key does arrive in the proof's own header, as RFC 9449 intends. That is
safe only because the key's thumbprint must equal the `jkt` in the already verified token
([0020](../decisions/0020-phase-3-dpop.md)).

## One token, one encoding

A token that can be written several ways invites two components to read it differently. So decoding is strict
wherever the specification allows it to be:

- base64url without line breaks or stray characters and with zero trailing bits, padded or not, so that one token
  has one text form;
- CBOR deterministically encoded, as section 4.5 requires apart from map order: shortest forms, no indefinite
  lengths, floats in their shortest exact form, integral values as integers;
- duplicate map keys refused everywhere, since a reader that takes the first and another that takes the last would
  disagree about the same token.

([0008](../decisions/0008-verification-rules.md), [0015](../decisions/0015-reconciling-with-cta-5007-b.md)).

## Fail closed, but only where the specification asks

A recipient must enforce some claims and may ignore others. The packages follow that line exactly, in both
directions:

- **A required claim is never ignored.** While a required claim was not yet built, tokens carrying it were refused
  as unsupported, so that a token restricted to one URI could not be accepted for every URI.
- **An optional claim is ignored unless the caller supplies what it needs.** `catreplay` needs a record of used
  `cti` values, `catgeoiso3166` a client location, `catalpn` and `cattpk` the TLS connection. Without those, the
  claim is ignored, as section 4.5 allows; with them, it is enforced.
- **Once supplied, missing facts refuse.** A location lookup that failed, or a connection that is not TLS, refuses
  a token that depends on it, since accepting it would let a failure bypass the restriction.

Ambiguities in the specification are settled toward refusal and written down where they are settled
([0017](../decisions/0017-request-claims.md), [0021](../decisions/0021-optional-claims.md)).

## Time is exact, and has no leeway

CTA-5007-B forbids leeway on `exp` and `nbf` (sections 4.6.3 and 4.6.4), so the issuer, not the recipient, decides
any margin. Dates may be integers or fractions of a second, and they are compared exactly, to the nanosecond,
rather than rounded. `cwt.Verifier`, for general CWTs, keeps a leeway setting, because RFC 8392 inherits JWT's
allowance for clock skew; `cat` never uses it ([0010](../decisions/0010-validity-window.md),
[0016](../decisions/0016-cwt-claims-shape.md)).

## The validator holds no state and few opinions about its surroundings

Nothing in `cat` remembers anything between calls. Facts that need memory or context, such as which `cti` values
were used, where the client is, or what ALPN was negotiated, come from the caller through `Validator` and `Request`
fields. That keeps the validator correct across many machines, where only the operator knows how state is shared,
and keeps it honest about what it cannot see ([0021](../decisions/0021-optional-claims.md)).

## Issuing is opt-in

Renewing tokens (`catr`) and minting them for responses (`catif`) means signing, and a recipient that signs holds
keys others must trust. So issuing is off unless a `Validator` is given an `Issuance`. A renewed token changes only
`exp`, `iss`, `iat` and `cti`, and carries every other claim exactly as received, including ones this package does
not understand ([0022](../decisions/0022-issuance-catr-catif.md)).

## A response to a token is private, whatever the handler does

Section 4.3.1.5.1 has a recipient that processed a token mark its response private, so that shared caches do not
store it. The middleware enforces this in the response writer it hands the handler, so it holds whatever the
handler sets. It drops `public`. It replaces a `private` that names fields, since that form lets a shared cache
store the rest of the response. And when a handler writes no body, it finishes the header itself, because the
server would otherwise send the response without passing through the writer at all
([0019](../decisions/0019-http-integration.md), [0023](../decisions/0023-polish-before-publication.md)).

## Deliberately not supported

- **`geohash`** takes its rules from another standard, CTA-5009-A, which this project has not read; building it
  would mean guessing.
- **Composition claims** (`and`, `or`, `nor`, `crit`, `env`) are only proposed, in an IETF draft that section 3.1
  cites. They have no assigned claim keys, and CTA-5007-B says they cannot be used yet, so there is nothing to
  build until they are published.
- **`catgeoalt`** needs a client's altitude, which almost no recipient knows; it waits for one that does.
- **`catgeocoord`** must arrive in an encrypted claim, and this package does not decrypt, so supporting it could
  only mean refusing it. It is ignored, which the specification allows.
- **Encrypted tokens** are optional for recipients and have no mandatory algorithm; decision 0005 deferred them.
- **COSE messages with several signers or recipients** are allowed by RFC 8392 but not used by any CAT example or
  known issuer, and need per-recipient key handling. They are the most likely next addition, by their own decision.

The rule behind all of these: verification is not shipped without something independent to check it against
([0008](../decisions/0008-verification-rules.md), [0015](../decisions/0015-reconciling-with-cta-5007-b.md),
[0021](../decisions/0021-optional-claims.md)).

## How the design is held in place

The code is checked against outside vectors wherever they exist: RFC 8392's examples (protected tests that only the
owner may change), the COSE working group's vectors, RFC 7638's thumbprint, RFC 9449's example proof, and, for
anyone with a copy, CTA-5007-B's own examples. Parsers are fuzzed, and mutation testing finds tests that pass
without checking much. How that process works, and why, is in [process.md](process.md).
