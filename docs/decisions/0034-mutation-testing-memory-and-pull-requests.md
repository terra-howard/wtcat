# 0034. Mutation testing: a memory cap, and pull requests

- **Status:** accepted, 2026-11-18
- **Decided by:** Terra Howard, that mutation testing runs on pull requests' changes and that the full runs are made to
  survive (*"Yes, let's do that proposal"*). Its shape was chosen by Claude under her delegation.
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-18).

## Question asked

Decision 0028 gave the full mutation runs two workers, guessing that CPU starvation made GitHub's hosted runners lose
contact. They kept losing contact: `cathttp` failed on every push to `main`, after 47 to 49 minutes, and `cat` often.
Separately, gaps in new tests were found only after merge, when `main`'s run went red. What would an expert change?

## What was measured

Tasks 68 and 68b in the measurements.

- **Not disk.** A full `cathttp` run grows Go's build cache by about 3.3 MB a mutant, about 1.2 GB in all, well within
  a runner's disk.
- **Memory.** One mutant turned a loop counter around (`INCREMENT_DECREMENT`), and its test process grew to 9.5 GB in a
  minute, leaving a 12 GB machine 156 MB free. The owner's log from a failed hosted run ends on the same kind of
  mutant just before the runner shut down. With the timeout at ten times the baseline, such a mutant has time to
  exhaust a runner's 16 GB.
- **A cap fixes it.** With each process's address space capped at 4 GiB, the same run finished, its largest test
  process stayed at 1.5 GB, and the result was unchanged, except that the runaway mutant now crashes and counts as
  killed.
- **Gremlins can test a diff.** `--diff <ref>` mutates only changed lines. On roadmap item 2's branch, it took
  4.5 minutes and found eight survivors in the new code that faults planted by hand had missed.

## Reasoning

- **Cap memory, in both workflows.** `ulimit -v 4194304` before Gremlins limits every process it starts. A runaway
  mutant then fails its test, which is the right verdict, since the tests did notice it misbehaving. Four GiB is far
  above any honest test here, and two workers at the cap still fit a hosted runner.
- **Keep two workers and the 120-minute limit** from decision 0028. They cost little, and the measurements did not
  show them to be wrong.
- **Mutation-test pull requests, on their changes only.** A new workflow, `mutation-diff.yml`, runs Gremlins with
  `--diff` against the pull request's base. Every surviving mutant is annotated on its line, where the reviewer sees
  it.
- **Judge a diff only when it has enough mutants.** With ten or more, the efficacy on the changed code must be at
  least 92.5%, the lowest package threshold. With fewer, a single equivalent mutant would decide the result, so they
  are annotated but not judged.
- **A different vacuity check for diffs.** Decision 0028 refuses a full run in which no mutant lived, since every
  package has known equivalents. A diff can rightly have none, so the pull-request workflow instead refuses any
  Gremlins config that sets `test-cpu`, the setting that made runs vacuous.
- **Considered and left out:** a step freeing disk space, since disk was not the problem; non-integration mode, which
  would be faster but lets mutants that only another package's tests catch survive; a lower timeout coefficient,
  which would not have saved the runner, since the runaway took its memory within a minute.

## Consequences

- `.github/workflows/mutation.yml` caps memory before Gremlins. `.github/workflows/mutation-diff.yml` and
  `.github/gremlins/diff.yaml` are new.
- A pull request whose new tests miss faults in its code shows a red check, with the faults annotated, before merge.
- The diff run's threshold is one number for all packages. If that proves too blunt, per-package diff thresholds
  are the next step.
