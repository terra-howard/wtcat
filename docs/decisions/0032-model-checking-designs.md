# 0032. Model-checking designs with TLA+, as an experiment

- **Status:** accepted as an experiment, 2026-11-18
- **Decided by:** Terra Howard, that the project tries it (*"Yeah, I'd like for us to try that experimentally"*). Its
  shape was chosen by Claude under her delegation.
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-18).

## Question asked

The project's checks so far test code: outside vectors, fuzzing, mutation testing. None of them checks a design
before there is code, and the roadmap's MOQT work has designs where the hard part is state and ordering: tokens
revalidated on long sessions, `catreplay` bound to one connection, replay state shared across relays. Would
model-checking such designs with TLA+ and its model checker, TLC, be worth it here?

## Reasoning

- **Where it fits.** TLC explores every interleaving of a small model's actions, up to a bound, and reports any
  that breaks a stated invariant. That finds design faults that no test of finished code can, because a test runs
  one interleaving. It fits features with concurrency or state shared between parties. It does not fit the pure
  functions this project mostly has, which the existing practices cover well.
- **Proof assistants such as Lean are left out.** They suit small pure functions with a crisp specification, which
  here are already fuzzed, property-tested and mutation-tested, at a cost far larger than what they would add.
- **Models and code must stay tied.** A model can drift from the code it describes. So each model's invariants are
  also written as Go property tests of the code, where code exists, and the decision record says which test carries
  which invariant.
- **An experiment, with an exit.** The practice stays if, over its first two models, it finds a design fault the
  other practices would not have found before code, or costs little enough to keep as documentation. Otherwise it
  is dropped and this record says why.

## Decision

1. For a feature with concurrency or state shared between parties, its decision record comes with a TLA+ model in
   `specs/<name>/` and the invariants it must keep. TLC must find no violation in the configuration chosen for the
   design before the feature is built.
2. Each model's configurations, including ones expected to fail, are listed with their predicted outcome in the
   measurements before TLC runs, as for any measurement (AGENTS.md rule 7).
3. Each invariant is carried into a Go property test where the code exists.
4. **The first model is `specs/connectionreplay/`**, for the roadmap's connection-scoped replay. It checks
   draft-ietf-moq-c4m's rule that a `catreplay` 1 token is accepted on one connection only, across two relays, with
   a store that is shared or per relay, and with "bind if unbound" done atomically or as a lookup then a write. Its
   invariant `OneConnection` is carried by `TestCatreplayConcurrentUseAcceptsOnce`, which checks the same property
   for single use over HTTP today, and fails against a non-atomic `Replay`.
5. Running TLC needs Java and the TLA+ tools. How they are installed on the build machine and in CI is the
   owner's choice, and is recorded here when made.

## Consequences

- `Validator.Replay`'s documentation now says the hook must record and report atomically, and must be shared by
  every recipient accepting the same tokens. The model shows both conditions are needed, not just one.
- The second model is the natural next one: `moqt-reval` revalidation racing expiry, when that work begins.
