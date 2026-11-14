# wtcat

*Working title.* A Go validator for the Common Access Token (CAT, CTA-5007), a CBOR Web Token format that CDNs use
to decide whether a request may fetch content.

**Status:** phase 1. Package `cwt` decodes CBOR Web Tokens and verifies COSE_Mac0 (HMAC 256/64 and 256/256) and
COSE_Sign1 (ES256 and PS256), checks the validity window, and offers a `Verifier` with an algorithm allow-list,
key lookup by `kid` and a clock. The parsers are fuzzed. The census gate is green. CAT's own claims come next.

There are two deliverables of equal weight: a validator worth using, and the development process it is built with, written down in [docs/explanation/process.md](docs/explanation/process.md)
so later projects can reuse it.

- [docs/explanation/process.md](docs/explanation/process.md) explains how work happens here and why.
- [docs/how-to/verify-a-token.md](docs/how-to/verify-a-token.md) shows how to verify a token with package `cwt`.
- [docs/decisions/](docs/decisions/) holds one record per decision, proposed or accepted.
- [docs/reference/measurements.md](docs/reference/measurements.md) records each task's prediction and outcome.
- [AGENTS.md](AGENTS.md) is the steering file every coding agent reads first.

Documentation follows [Diátaxis](https://diataxis.fr/): tutorials, how-to guides, reference and explanation, kept
as separate pages. So far there is explanation, a how-to guide, reference and decision records.
