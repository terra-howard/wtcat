# 0036. Revalidating tokens on long MOQT streams

- **Status:** accepted, 2026-11-18
- **Decided by:** Claude, under Terra Howard's delegation (the MoQT roadmap, item 3).
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-18).

## Question asked

draft-ietf-moq-c4m's `moqt-reval` claim asks a relay to revalidate the token of an ongoing stream at least every so
many seconds, and to stop the stream once the token is no longer acceptable. Decision 0035 refuses tokens carrying
it until this decision. How should `cat` support it?

## What the draft establishes

Paraphrased, section "moqt-reval claim": the value is a number of seconds. Zero, or no claim, means the token must
not be revalidated. A recipient must reject a token whose interval is shorter than it can revalidate, and one that
cannot revalidate at all must reject every token carrying the claim. Revalidating is validating again as if new,
and checks that cannot change the outcome, such as the signature when the keys have not changed, may be skipped. The
claim belongs in the base claim set only.

## Reasoning

- **The relay runs the timer; `cat` reports the interval.** A validator holds no state (the design explanation), so
  it cannot run a stream's timer. `Token.Revalidate` reports the interval, and the caller revalidates by calling
  `ValidateRequest` again before it elapses, counting from the last successful check. The second TLA+ model,
  `specs/revalidation/`, checks that this bounds how long a stream can run on a dead token by the interval, and that
  revalidating less often than the interval does not (task 70).
- **The recipient says what it can do.** `Validator.MinRevalidation` is the shortest interval the caller is prepared
  to honour. A token asking for less is refused as unsupported. Zero means the caller does not revalidate, so every
  token with a positive `moqt-reval` is refused. That is fail-closed by default, as the draft requires.
- **The same rule for HTTP.** A token with `moqt-reval` names MOQT streams, but a recipient that serves it over HTTP
  is just as unable to revalidate, so the rule does not depend on the request kind.
- **The value.** A non-negative number, integer or floating point, finite, with fractions of a second kept. A
  negative, NaN or infinite value, or one of another type, is malformed. Zero means no revalidation, as the draft
  says.
- **Skipping checks is left to callers.** The draft allows skipping the signature on revalidation. Here every
  revalidation is a full validation, which costs microseconds (task 59), and avoids a cached state that could go
  stale.

## Decision

1. `cat` decodes `moqt-reval` at `Validator.MOQTRevalKey` (default -65538) as above, and reports it as
   `Token.Revalidate`, a `time.Duration`, zero when absent or zero.
2. A token whose `Revalidate` is positive and shorter than `Validator.MinRevalidation`, or positive while
   `MinRevalidation` is zero, is refused with `cwt.ErrUnsupported`.
3. Tests use the draft's `moqt_multi_scope` vector, which carries `moqt-reval` 300, and rule tests.
