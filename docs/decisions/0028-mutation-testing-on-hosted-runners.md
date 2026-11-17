# 0028. Mutation testing on hosted runners

- **Status:** accepted, 2026-11-17
- **Decided by:** Claude, under Terra Howard's delegation (2026-11-17, after publication).
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-17).

## Question asked

After publication, the mutation workflow (decision 0024) failed on GitHub: `cathttp` and `cat` jobs ended after 49
and 69 minutes with "The hosted runner lost communication with the server", GitHub's annotation for a runner
starved of CPU or memory, and another `cathttp` job ran past half an hour. What would an expert change?

## What was measured

Tasks 60, 61 and 61b in the measurements.

- Generated RSA test keys made the suite slower and less steady, but did not cause timeouts on an idle machine.
  They are replaced by fixed test keys anyway.
- On four CPUs, a hosted runner's size, the unchanged configuration finished `cathttp` in under six minutes with
  memory to spare. **The failure on GitHub did not reproduce.**
- **Gremlins v0.6.0's `test-cpu` setting is broken.** It passes `-cpu N` to `go test` as a single argument, which
  `go test` refuses with exit status 1, and Gremlins counts exit status 1 as a killed mutant. The run reported 100%
  efficacy in eight seconds and passed both thresholds. In integration mode it also divides the value by itself.
- With `workers: 2` alone, `cathttp` gave the same result as the unchanged run, mutant for mutant, in about half
  again the time.

## Reasoning

- **Two workers.** Gremlins defaults to one worker per CPU, and in integration mode each worker runs the whole
  suite, which compiles and tests every package at once. Two workers on four CPUs leaves headroom for the compiler
  and the runner itself. This is the plausible cause of the starved runners, not a demonstrated one, so the cost is
  kept low: half again the time, with the result unchanged.
- **Never `test-cpu`** with this version. The configs say so beside `workers`.
- **A guard against vacuous runs.** The broken setting showed that a run can fail in a way both thresholds miss:
  mutant coverage only notices mutants that time out, not mutants that were never really tested. Every package has
  mutants already classified as equivalent, which no test can kill, so a run in which none lived cannot be real.
  The workflow writes Gremlins' JSON report and fails the job if `mutants_lived` is below 1. The floor is 1, not
  the count of known equivalents, so that removing an equivalent mutant by rewriting code does not break the gate.
  If a package ever has no equivalent mutants left, this floor has to change, and this record says why.
- **A longer job limit,** 120 minutes instead of 90, for the slower runs.

## Consequences

- `.github/gremlins/<package>.yaml` sets `workers: 2`. `.github/workflows/mutation.yml` passes `-o gremlins.json`,
  adds the "Refuse a vacuous run" step, and allows 120 minutes.
- If the runners still lose contact, the next step is measurement on GitHub itself, since the failure does not
  reproduce elsewhere.
- Gremlins' `test-cpu` bug is upstream's. Whether to report it is the owner's decision.
