# 0033. The COSE typ header

- **Status:** accepted, 2026-11-18
- **Decided by:** Claude, under Terra Howard's delegation (the MoQT roadmap, 2026-11-18).
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

## Question asked

Decision 0008 refuses any COSE header parameter other than `alg` and `kid`. The test vectors of
draft-ietf-moq-c4m (CAT for MOQT, the roadmap's first entry) all carry `typ` (label 16, RFC 9596) with the value
"CAT" in their protected header, so wtcat refuses every one of them. Should it accept `typ`, and what should it do
with the value?

## Reasoning

- **Accept it.** RFC 9596 registers `typ` for COSE so that a message can say what kind of thing it is, as JWT's
  `typ` does. CTA-5007-B does not mention it and does not forbid it. Refusing a registered header that names the
  token's own type gains nothing and blocks MOQT interoperability.
- **Check it, rather than ignore it.** Explicit typing is a defence against one kind of token being accepted as
  another (RFC 8725 section 3.11). The case here is concrete: the MOQT draft's DPoP proofs are COSE_Sign1 CWTs
  typed "dpop-proof+cwt", and a proof must never be accepted as an access token. So a CAT with a `typ` must name an
  accepted type.
- **Which types.** By default, only "CAT", the value the MOQT draft's vectors use, compared exactly. A recipient
  can widen the list through `Validator.Types`. A token without `typ` stays acceptable, since CTA-5007-B does not
  require one.
- **Where.** RFC 9596 allows `typ` in either header, and decision 0008's rule that a parameter may not appear in
  both still applies. Unlike `alg`, a `typ` in the unprotected header is accepted, since nothing is decided by it
  that the signature does not cover: a token whose `typ` was altered there is refused or accepted on the type check
  alone, and its MAC or signature still has to verify.
- **Its value.** RFC 9596 allows a text string (a media type) or an unsigned integer (a CoAP content format). An
  integer names no CAT type, so it is refused by the type check, not as malformed. Any other CBOR type is
  malformed.
- **`cwt` stays general.** `cwt` accepts and reports `typ`, in `Message.Type`, and leaves the policy to the caller.
  `cat` applies it.

## Decision

1. `cwt` accepts header parameter 16 in either header, as a text string or an unsigned integer, and reports it as
   `Message.Type` (empty when absent; an integer is formatted in decimal with a leading `#`, so it can never equal
   a media type).
2. `cat.Validator.Types` lists the `typ` values accepted. When it is empty, the list is "CAT". A token whose `typ` is
   present and not listed is refused with `cwt.ErrUnsupported`.
3. Tests use draft-ietf-moq-c4m's Appendix A token-validation and token-structure vectors, at the editor's copy
   `55d8a2e`, as fixtures with their source and licence recorded.
