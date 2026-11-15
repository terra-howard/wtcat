# wtcat

*Working title.* A Go validator for the Common Access Token (CAT, CTA-5007), a CBOR Web Token format that CDNs use
to decide whether a request may fetch content.

**Status:** phases 1 to 4 of [decision 0015](docs/decisions/0015-reconciling-with-cta-5007-b.md). Package `cwt`
decodes CBOR Web Tokens, verifies COSE_Mac0 (HMAC 256/64 and 256/256) and COSE_Sign1 (ES256 and PS256), with a
`Verifier` and, for profiles such as CAT, `VerifyMessage` with keys bound to one algorithm, and issues tokens
(`Issue`). Package `cat` validates
Common Access Tokens: strict base64url, deterministic encoding, `iss`, `aud`, `exp` and `nbf` with no leeway, and
`catv`, and, given the request, `catm`, `cath`, `catu`, `catnip`, and `cnf` with `catdpop`, checking the request's DPoP
proof (RFC 9449) with a narrow verifier of its own. Every claim CTA-5007-B requires recipients to support is
enforced. Of the optional claims, `catreplay`, `catgeoiso3166`, `catalpn` and `cattpk` are enforced when the caller
supplies what they need, and with an `Issuance` configured, `catr` renews tokens and `catif` shapes the response
to a refused one, minting tokens where it asks; the rest are ignored, as the specification allows. The full list of
supported claims is in the package documentation. The parsers are fuzzed. The census gate is green.

Package `cathttp` finds tokens in HTTP requests as section 4.4 orders them, removes each from the URI before `catu`,
and wraps a handler: the `catif` response or 401 without an acceptable token, `Cache-Control: private` whenever a
token was processed, token-bearing fields removed before forwarding, and `catr` renewals by cookie, header or
redirect.

The specification is CTA-5007-B, *Common Access Token*, free to download from the
[Consumer Technology Association](https://www.cta.tech/). This repository does not reproduce it
([decision 0014](docs/decisions/0014-using-cta-5007-b-in-public.md)). If you have a copy, you can run the tests
against its own HMAC 256/256 and PS256 examples: `pdftotext` it (without `-layout`), then
`go run ./cmd/ctaexamples cta.txt` and `go test -tags cta ./cat`. The extracted examples stay on your machine.

There are two deliverables of equal weight: a validator worth using, and the development process it is built with, written down in [docs/explanation/process.md](docs/explanation/process.md)
so later projects can reuse it.

- [docs/tutorials/protect-a-server.md](docs/tutorials/protect-a-server.md) walks a newcomer through protecting a small
  server end to end.
- [docs/explanation/design.md](docs/explanation/design.md) explains why the validator is built the way it is.
- [docs/explanation/process.md](docs/explanation/process.md) explains how work happens here and why.
- [docs/how-to/validate-a-cat.md](docs/how-to/validate-a-cat.md) shows how to validate a CAT with package `cat`.
- [docs/how-to/verify-a-token.md](docs/how-to/verify-a-token.md) shows how to verify a general CWT with package `cwt`.
- [docs/how-to/deploy-behind-a-proxy.md](docs/how-to/deploy-behind-a-proxy.md) shows what to set behind a proxy that
  terminates TLS.
- [docs/how-to/run-the-cta-example-tests.md](docs/how-to/run-the-cta-example-tests.md) runs the tests against
  CTA-5007-B's own examples from your copy.
- [docs/decisions/](docs/decisions/) holds one record per decision, proposed or accepted.
- [docs/reference/measurements.md](docs/reference/measurements.md) records each task's prediction and outcome.
- [AGENTS.md](AGENTS.md) is the steering file every coding agent reads first.

Documentation follows [Diátaxis](https://diataxis.fr/): tutorials, how-to guides, reference and explanation, kept
as separate pages, plus decision records.
