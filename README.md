# wtcat

*Working title.* A Go validator for the Common Access Token (CAT): the CBOR Web Token format of CTA-5007-B, which
CDNs use to decide whether a request may fetch content.

```go
v := &cat.Validator{Keys: keys, Audiences: []string{"cdn.example"}} // keys returns the cat.Key for a kid
auth := &cathttp.Authorizer{Validator: v}
http.Handle("/videos/", auth.Middleware(videos))
```

Requests with an acceptable token reach `videos`. Others are answered 401, or as the refused token's `catif` claim
asks. [The tutorial](docs/tutorials/protect-a-server.md) builds this end to end in about fifteen minutes.

## What it does

- **`cwt`** decodes CBOR Web Tokens (RFC 8392), verifies COSE_Mac0 (HMAC 256/64 and 256/256) and COSE_Sign1
  (ES256 and PS256), and issues tokens.
- **`cat`** validates CATs as CTA-5007-B requires: a strict text form and deterministic encoding, keys bound to
  one algorithm and one issuer, every claim the specification requires recipients to support, and the optional
  claims whose context the caller supplies. Given signing keys, it renews tokens (`catr`) and answers refusals as
  `catif` asks.
- **`cathttp`** finds tokens in HTTP requests in the order section 4.4 sets, removes each from the URI before
  `catu` is checked, and wraps a handler: refusals, `Cache-Control: private`, renewals, and token-bearing fields
  removed before forwarding.
- **`catmoqt`** does the same for a MOQT relay, under draft-ietf-moq-c4m and draft-ietf-moq-transport-22, with no
  MOQT library underneath: it keeps a session's authorization token cache, judges the CATs a request carries, and
  answers with a grant or the draft's error code.

The `cat` package documentation lists exactly which claims are enforced and which are ignored.
[The design explanation](docs/explanation/design.md) says what is left out, such as AES-CCM encryption, and why.

## Status

Published as `v0.1.0`, before 1.0, so the API may still change between minor versions. Install with
`go get github.com/terra-howard/wtcat@latest`; package documentation is on
[pkg.go.dev](https://pkg.go.dev/github.com/terra-howard/wtcat). Decisions 0006 to 0040 were made under the owner's
delegation and reviewed and approved by her; any later one is marked unreviewed until she reviews it. The tests include RFC 8392's examples and the COSE
working group's vectors as protected tests and, run locally from a copy of the specification, CTA-5007-B's own HMAC and
PS256 examples. The parsers are fuzzed, and mutation testing checks the tests. Security reports go through
[SECURITY.md](SECURITY.md).

## The specification

CTA-5007-B, *Common Access Token*, is free to download from the [Consumer Technology
Association](https://www.cta.tech/). This repository does not reproduce it
([decision 0014](docs/decisions/0014-using-cta-5007-b-in-public.md)). With a copy, you can
[run the tests against its own examples](docs/how-to/run-the-cta-example-tests.md).

## Two deliverables

The validator and the development process it is built with matter equally. The process is explained in
[docs/explanation/process.md](docs/explanation/process.md), so that later projects can reuse it.
[AGENTS.md](AGENTS.md) is the steering file every coding agent reads first.

## Documentation

Organized by [Diátaxis](https://diataxis.fr/):

- **Tutorial:** [protect a small server](docs/tutorials/protect-a-server.md), end to end, for a newcomer.
- **How-to guides:** [validate a CAT](docs/how-to/validate-a-cat.md),
  [verify a general CWT](docs/how-to/verify-a-token.md), [deploy behind a proxy](docs/how-to/deploy-behind-a-proxy.md),
  and [run the tests against CTA-5007-B's examples](docs/how-to/run-the-cta-example-tests.md).
- **Reference:** the package documentation (`go doc`), [every error and what it means](docs/reference/errors.md),
  and the [measurements](docs/reference/measurements.md) of each task's prediction and outcome.
- **Explanation:** [what this is for, in plain words](docs/explanation/in-plain-words.md),
  [why the validator is built the way it is](docs/explanation/design.md), and
  [how work happens here, and why](docs/explanation/process.md).
- **Decisions:** [one record per decision](docs/decisions/), proposed or accepted.
- **Roadmap:** [what is planned next](ROADMAP.md), starting with CAT for Media over QUIC Transport.

Licensed under the Apache License 2.0.
