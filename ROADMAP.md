# Roadmap

What is planned, and what each piece waits on. Nothing here is a promise of a date. Each item becomes its own
decision record before it is built, as every feature has.

## MoQT: CAT for Media over QUIC Transport

**Source:** the IETF Media over QUIC working group's draft *Authorization scheme for MOQT using Common Access
Tokens*, draft-ietf-moq-c4m. It was read at the editor's copy in <https://github.com/moq-wg/CAT-4-MOQT>, commit
`55d8a2e` (2026-11-02), which follows the published -02 and refers to moq-transport-22. It is a working draft: its claim
keys are not assigned yet (its test vectors use private-use keys), and its details can change.

**What it changes.** Over HTTP, a CDN checks a CAT against each request's URL. Over MoQT, the relay checks a token
when the session is set up, over WebTransport or raw QUIC, and then for every MOQT action (SUBSCRIBE, FETCH, PUBLISH,
PUBLISH_NAMESPACE and the rest), against a new `moqt` claim. That claim lists the actions allowed on which track
namespaces and track names, and denies everything else.

**What wtcat needs, roughly in order:**

1. **Accept the COSE `typ` header (16).** The draft's test tokens carry `typ` in their protected header, and decision
   0008 refuses every header other than `alg` and `kid`. This is the smallest change and comes first, since without
   it no MoQT token validates.
2. **The `moqt` claim**, decoded and matched under the draft's rules: scopes of actions, namespace and track
   matches (exact, prefix or suffix, bytewise), a nil terminator that pins the namespace length, default deny, and
   refusal of unknown keys in the claim. It also needs a request type for MOQT actions (the action, the Track
   Namespace fields, the Track Name) beside `cat.Request`'s HTTP fields. Claim keys stay configurable until IANA
   assigns them.
3. **`moqt-reval`**: give the caller the revalidation interval it must honour, and refuse tokens asking for
   revalidation more often than the caller supports.
4. **Connection-scoped replay.** The draft reads `catreplay` 1 as "one connection" for MOQT, so the replay hook has
   to see the connection as well as the `cti`.
5. **DPoP proofs as CWTs.** Thumbprint confirmation with `ckt` (RFC 9679), and COSE_Sign1 proofs with `kccs`,
   `actx` and `ath`, checked per action. The existing COSE_Sign1 verification and RFC 9449 DPoP code are the
   starting points.
6. **Composite claims** (`or`, `and`, `nor`), which the draft's multi-scope examples use. Their own IETF draft has
   to settle claim keys first ([the design explanation](docs/explanation/design.md) leaves them out for that reason).
7. **A MOQT integration package**, the counterpart of `cathttp`, that a Go MOQT relay calls at SETUP and for each
   action. Which Go MOQT library it targets is still to be chosen.

**Independent checks:** the draft's Appendix A test vectors, run as protected-style fixtures with their source
recorded, and any other implementation's tokens, as decision 0026 does for HTTP CATs.

## Waiting on others

- **Composite claims**: their claim keys, for item 6 above and for HTTP CATs alike.
- **`catgeoalt`**: a caller that knows a client's altitude.
- **AES-CCM**: an issuer that needs it (decision 0030).
