# wtcat

*Working title.* A Go validator for the Common Access Token (CAT, CTA-5007), a CBOR Web Token format that CDNs use
to decide whether a request may fetch content.

**Status:** phase 1. The census gate works; the validator is a stub, so the protected tests fail by design until
it is written. There are two deliverables of equal weight: a validator worth using, and the
development process it is built with, written down in [docs/explanation/process.md](docs/explanation/process.md)
so later projects can reuse it.

- [docs/explanation/process.md](docs/explanation/process.md) explains how work happens here and why.
- [docs/decisions/](docs/decisions/) holds one record per decision, proposed or accepted.
- [AGENTS.md](AGENTS.md) is the steering file every coding agent reads first.

Documentation follows [Diátaxis](https://diataxis.fr/): tutorials, how-to guides, reference and explanation, kept
as separate pages. So far there is explanation and decision records.
