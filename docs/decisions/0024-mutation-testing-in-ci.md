# 0024. Mutation testing in CI

- **Status:** accepted, 2026-11-15
- **Decided by:** Terra Howard, that mutation testing runs in CI. Its shape and thresholds were chosen by Claude
  under her delegation, pending her review.
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-17).

## Question asked

Decision 0013 runs Gremlins by hand, and the measurements record each run. Should it also gate the build, and how?

## Reasoning

- **A threshold turns a measurement into a gate.** New code that lands without tests able to notice its faults
  then fails the build, as a red test does, instead of waiting for someone to run Gremlins by hand.
- **One efficacy threshold per package, a little below today's scores.** Task 55 measured `cwt` at 97.16%, `cat`
  at 93.60% and `cathttp` at 98.25%. The thresholds are 96%, 92.5% and 97%. Each margin is about one point, roughly
  two new survivors in `cwt`, nine in `cat` and three in `cathttp`. The equivalent mutants already recorded are in
  today's scores, so the margin is room for new code.
- **A mutant-coverage threshold too, because efficacy alone can pass vacuously.** Efficacy counts only killed and
  lived mutants. A mutant that times out counts as neither, so a run where most mutants time out can still report a
  high efficacy. One check run did exactly that: `cwt` reported 100.00% with 27 mutants killed and 149 timed out.
  Mutant coverage fell to 51.92% in the same run, so a coverage threshold (85% for `cwt`, 88% for `cat`, 82% for
  `cathttp`, each about 2.5 points below today's) makes such a run fail instead of pass.
- **The thresholds live in config files, `.github/gremlins/<package>.yaml`, not on the command line.** Gremlins
  v0.6.0 ignores `--threshold-efficacy` and `--threshold-mcover`: its configuration library, viper, returns a float
  flag's value as a string, and Gremlins reads the threshold with a type assertion that silently yields zero, which
  disables the check. Environment variables arrive as strings too. A YAML number arrives as a number. Found when the
  first version of the gate, using the flags, passed a run it should have failed. The config files also carry the
  other settings every measured run has used (`integration`, `timeout-coefficient: 10`, `invert-logical`,
  `invert-loopctrl`), so a local run with `--config` reproduces CI exactly.
- **Thresholds ratchet.** Raising one needs nothing. Lowering one needs a reason written here, because that is the
  move the gate exists to make visible.
- **Not on every push.** On 24 cores, `cat` takes about four minutes; a hosted runner has far fewer. The workflow runs
  on pushes to `main`, weekly, and by hand, while the fast gate in `ci.yml` stays on every push and pull request.
- **On a hosted runner.** Gremlins starts thousands of short-lived processes, which is cheap on a build machine and
  costly on one doing other work, as the process explanation advises.

## Consequences

- Like `ci.yml`, the workflow is inert until the repository is on GitHub.
- When it fails on efficacy, the survivors it lists are either gaps, which get a test, or equivalent mutants, which
  are recorded in the measurements with their reasons. Only the second, and only with a reason here, can lower a
  threshold. When it fails on coverage, look first for timeouts before suspecting the tests.
- If a later Gremlins release reads its threshold flags properly, the config files still work; moving the
  thresholds back to the command line would gain nothing.
- The `go run ...@v0.6.0` form keeps Gremlins pinned and verified by Go's checksum database, and installs nothing.
