# 0031. Fuzzing deadline flakes in CI

- **Status:** accepted, 2026-11-17
- **Decided by:** Claude, under Terra Howard's delegation (2026-11-17, after publication).
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-17).

## Question asked

After PR #8 merged, the `gate` job on `main` failed in its fuzz step, although the same commit's pull request had
passed. The log showed `FuzzVerifySign1` reaching its 30 seconds, executions dropping to zero in the last second, and
`--- FAIL: FuzzVerifySign1 ... context deadline exceeded`, with no failing input written. Running every target again
locally found nothing. Is this a finding, and what should the gate do about it?

## Reasoning

- **It is not a finding.** When Go's fuzzer finds an input that fails, it writes it to `testdata/fuzz/` and says
  `Failing input written to`. Here nothing was written, and the target verifies one ES256 signature over a short
  input, so no slow input is plausible. The fuzzing coordinator stopping a worker mid-task at the time limit fits
  everything in the log.
- **But a gate that fails at random gets ignored**, and then it misses the real failure. So the step tells the two
  apart:
  - a written failing input fails the job at once;
  - any failure that is not a deadline also fails at once;
  - a deadline failure with no input gets one retry, with a warning in the log, and fails if it happens twice.
- **Considered and left out:**
  - Ignoring the error altogether, which would also hide a target that really hangs.
  - Running for a fixed number of executions instead of a time, which Go's `-fuzztime` allows as `Nx`. Speed on a
    hosted runner varies by a factor of ten (the log shows 9,740 to 105,423 executions a second), so a count
    long enough to mean something on a slow runner wastes minutes on a fast one.

## Consequences

- The fuzz step in `.github/workflows/ci.yml` runs each target through a small shell function with this rule. Its
  logic was checked locally against a stand-in `go` for each case: a pass, one flake, two flakes, a written input,
  and another failure.
- Two deadline failures in a row still fail the job. If that ever happens, treat it as a target that may really
  hang.
