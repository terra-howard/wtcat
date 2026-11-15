# wtcat

*Working title.* A Go validator for the Common Access Token (CAT, CTA-5007), a CBOR Web Token format that CDNs use
to decide whether a request may fetch content.

**Status:** phase 1 of [decision 0015](docs/decisions/0015-reconciling-with-cta-5007-b.md). Package `cwt` decodes
CBOR Web Tokens and verifies COSE_Mac0 (HMAC 256/64 and 256/256) and COSE_Sign1 (ES256 and PS256), with a
`Verifier` and, for profiles such as CAT, `VerifyMessage` with keys bound to one algorithm. Package `cat` validates
Common Access Tokens: strict base64url, deterministic encoding, `iss`, `aud`, `exp` and `nbf` with no leeway, and
`catv`, and, given the request, `catm`, `cath`, `catu` and `catnip`. It refuses tokens carrying `cnf` or `catdpop`,
which CTA-5007-B requires recipients to enforce and which need DPoP, not built yet, rather than ignoring them. The full list of
supported claims is in the package documentation. The parsers are fuzzed. The census gate is green.

The specification is CTA-5007-B, *Common Access Token*, free to download from the
[Consumer Technology Association](https://www.cta.tech/). This repository does not reproduce it
([decision 0014](docs/decisions/0014-using-cta-5007-b-in-public.md)). If you have a copy, you can run the tests
against its own HMAC 256/256 and PS256 examples: `pdftotext` it (without `-layout`), then
`go run ./cmd/ctaexamples cta.txt` and `go test -tags cta ./cat`. The extracted examples stay on your machine.

There are two deliverables of equal weight: a validator worth using, and the development process it is built with, written down in [docs/explanation/process.md](docs/explanation/process.md)
so later projects can reuse it.

- [docs/explanation/process.md](docs/explanation/process.md) explains how work happens here and why.
- [docs/how-to/validate-a-cat.md](docs/how-to/validate-a-cat.md) shows how to validate a CAT with package `cat`.
- [docs/how-to/verify-a-token.md](docs/how-to/verify-a-token.md) shows how to verify a general CWT with package `cwt`.
- [docs/decisions/](docs/decisions/) holds one record per decision, proposed or accepted.
- [docs/reference/measurements.md](docs/reference/measurements.md) records each task's prediction and outcome.
- [AGENTS.md](AGENTS.md) is the steering file every coding agent reads first.

Documentation follows [Diátaxis](https://diataxis.fr/): tutorials, how-to guides, reference and explanation, kept
as separate pages. So far there is explanation, a how-to guide, reference and decision records.
