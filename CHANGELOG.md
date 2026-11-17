# Changelog

All notable changes to this module are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).
Before 1.0, a minor version may change the API.

## [Unreleased]

## [0.1.0] - 2026-11-17

The first public release.

### Added

- **`cwt`**: decoding of CBOR Web Tokens (RFC 8392); verification of COSE_Mac0 (HMAC 256/64, HMAC 256/256) and
  COSE_Sign1 (ES256, PS256) with keys bound to one algorithm; exact validity checks with no leeway; a `Verifier`
  with an algorithm allow-list; and token issuance.
- **`cat`**: validation of Common Access Tokens as CTA-5007-B requires: a strict base64url text form, a length limit,
  deterministic encoding and tag rules, and every claim recipients must support (`iss`, `aud`, `exp`, `nbf`, `cti`,
  `sub`, `iat`, `catv`, `catnip`, `catu`, `catm`, `cath`, `cnf` with `jkt`, and `catdpop`, including RFC 9449 DPoP
  proofs). Optional claims are enforced when the caller supplies their context (`catreplay`, `catgeoiso3166`,
  `catalpn`, `cattpk`) and ignored otherwise. Given signing keys, it renews tokens under `catr` and answers refusals
  as `catif` asks.
- **`cathttp`**: finding tokens in HTTP requests in the order section 4.4 sets, removing each from the URI before
  `catu` is checked, and middleware that answers refusals, marks responses private, applies renewals, and removes
  token-bearing fields before forwarding.
- Protected conformance tests from RFC 8392's examples, gated by `go run ./cmd/census`; the COSE working group's
  vectors; fuzz targets for every parser; and mutation testing with thresholds in CI.
- Documentation by Diátaxis: a tutorial, how-to guides, an error reference, the design and process explanations,
  and decision records 0001 to 0024.

### Not supported

Encrypted tokens, COSE messages with several signers or recipients, `geohash`, `catgeoalt`, `catgeocoord` and the
proposed composition claims. `catpor` and `catifdata` are ignored. [The design explanation](docs/explanation/design.md) says why for each.

[Unreleased]: https://github.com/terra-howard/wtcat/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/terra-howard/wtcat/releases/tag/v0.1.0
