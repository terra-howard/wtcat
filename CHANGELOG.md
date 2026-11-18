# Changelog

All notable changes to this module are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).
Before 1.0, a minor version may change the API.

## [Unreleased]

### Added

- **MoQT support**, following draft-ietf-moq-c4m (decisions 0033 and 0035 to 0038):
  - the COSE `typ` header, reported as `cwt.Message.Type` and checked against `cat.Validator.Types`;
  - the `moqt` claim, judged for a `cat.Request` whose `MOQT` field describes the action, with `cat.ErrMOQT`, and
    its claim key configurable while IANA has not assigned one;
  - `moqt-reval`, reported as `Token.Revalidate` and bounded by `Validator.MinRevalidation`;
  - `catreplay` as one connection over MOQT, with `Connection.ID` and `Validator.BindConnection`;
  - DPoP proofs as CWTs, checked for each MOQT action: `cnf` with `ckt` (RFC 9679), `MOQTAction.Proof`,
    `Validator.ActxKey` and `AthKey`, which have no defaults, and `Validator.ProofReplay`, for ES256, ES384 and
    EdDSA proofs.
- **`catmoqt`** (decision 0039): authorization for a MOQT relay with no MOQT library underneath. A `Session` keeps
  draft-ietf-moq-transport-22's token cache, judges the CATs each request carries, and answers with a `Grant` or
  an `Error` holding the draft's code. `Grant.Recheck` revalidates for `moqt-reval`, judging a DPoP-bound token
  again without demanding its proof again (`cat.MOQTAction.Revalidating`).
- **Encrypted tokens** (decision 0030): `cwt.DecryptMessage` for COSE_Encrypt0 with AES-GCM, and
  `cat.Validator.DecryptionKeys`. `catgeocoord` is enforced, and the limits on unencrypted `catnip` and `geohash`
  do not apply to encrypted claims.
- **Several signers or recipients** (decision 0029): `cwt.VerifyMessage` accepts COSE_Sign and COSE_Mac, and
  `Message.KID` names the signer or recipient that verified.
- **`geohash`** is enforced when `Request.Location` has coordinates (decision 0027).
- Tests against tokens from three other CAT implementations (decision 0026), benchmarks for the hot paths, TLA+
  models of the designs that share state (`specs/`, decision 0032), mutation testing of each pull request's changes
  (decision 0034), Dependabot for Go modules and GitHub Actions (decision 0025), and a NOTICE file.

### Changed

- A token whose COSE `typ` is present and is not one of `Validator.Types`, by default "CAT", is now refused as
  unsupported (decision 0033).
- A `cnf` claim may now name `ckt`, which binds MOQT proofs; a token naming it is refused over HTTP with
  `cat.ErrProof`, where it was refused as unsupported (decision 0038).
- Full mutation runs cap each process's memory and use two workers, and refuse a configuration that sets
  `test-cpu`. A run in which no mutant lived is refused as vacuous, except for `catmoqt`, which has no mutant known
  to be equivalent (decisions 0028, 0034 and 0039).

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
