# 0026. Interoperability fixtures from other CAT implementations

- **Status:** accepted, 2026-11-17
- **Decided by:** Claude, under Terra Howard's delegation (2026-11-17, after publication).
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

## Question asked

Every check so far compares wtcat with a document: RFC 8392's examples, the COSE working group's vectors,
CTA-5007-B's own examples. None compares it with another implementation. Three public ones exist: Eyevinn's
node-cat (TypeScript), Fastly's rust-cat (Rust) and Frank Denis's zig-common-access-token (Zig), all under the MIT
licence. What would an expert take from them, and how?

## Reasoning

- **Tokens, not code.** AGENTS.md rule 5 allows tokens other implementations produce as fixtures, with their
  source and licence recorded, and forbids copying their code. Their test suites already contain tokens they
  produced, with the keys and the claims their authors expected.
- **Our verdicts come from the specification, not from theirs.** A fixture records what the other project
  expected and what CTA-5007-B requires. Where the two differ, the test asserts the specification and the
  difference is written down as a finding. A disagreement is evidence about one of the two implementations, and
  deciding which one needs the text, not a vote.
- **Static fixtures first.** Generating fresh tokens with each library would need Node, Rust and Zig toolchains on
  the build machine and in CI, for evidence the committed fixtures already give. That second step waits for its own
  decision, if the static set leaves a gap.
- **Pinned and attributed.** Each fixture names the repository, the commit, the file and line it came from, and the
  licence. The MIT licence asks that its notice travel with substantial portions; a handful of tokens is not that,
  but the source note carries each licence anyway, which costs nothing.
- **Expired tokens are still useful.** Most fixtures carry `exp` values in the past. The tests judge them at a
  fixed moment inside each token's window, as the other projects' own tests do, so the result does not depend on
  today's date.

## Decision

1. Fixtures live in `cat/testdata/interop/`, one JSON file per source project, each entry giving the token, the key
   and kid it was made with, the moment to judge it at, the source project's expected verdict, the verdict
   CTA-5007-B requires, and a note when the two differ. `cat/testdata/interop/SOURCES.md` records the repositories,
   commits and licences.
2. `cat/interop_test.go` runs every fixture through `cat.Validator` and asserts the specification's verdict.
3. Each disagreement found is recorded in the fixture's note and in the measurements, and reported upstream only
   by the owner's decision.
4. Live generation with the other libraries is deferred to a later decision.
