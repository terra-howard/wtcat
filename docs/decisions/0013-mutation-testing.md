# 0013. Mutation testing with Gremlins

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation for an experiment (see decision 0007). Pending her
  review; she may reverse it.

## Question asked

Decision 0003 left the mutation-testing tool for later. Seven tasks in, every implementation passed its tests on
the first compiled run. What would an expert do with that?

## Reasoning

Distrust it. Tests that pass first time may mean the code is right, or that the tests are too weak to notice it
being wrong. Mutation testing tells the two apart: it makes small deliberate faults in the code (flipping a
comparison, removing a negation) and checks that some test fails for each. A fault no test notices is a gap.

Candidates, checked through the GitHub API on 2026-11-14:

| Tool | Licence | Latest release |
|---|---|---|
| [go-gremlins/gremlins][gremlins] | Apache-2.0 | v0.6.0, 2025-12-06 |
| [avito-tech/go-mutesting][mutesting] | MIT | v2.3.1, 2025-12-26 |

Gremlins is chosen: same licence as this project, and it uses coverage to mutate only code the tests reach,
which keeps runs short.

## Decision

- Run it with `go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0`, pinned, so nothing is installed and
  `go.mod` gains no tool dependency.
- Record the score and every surviving mutant in `docs/reference/measurements.md`, with the prediction committed
  first.
- A surviving mutant in verification or parsing logic is treated as a missing test and fixed. One that only
  changes an error message's wording is recorded and left.

[gremlins]: https://github.com/go-gremlins/gremlins
[mutesting]: https://github.com/avito-tech/go-mutesting
