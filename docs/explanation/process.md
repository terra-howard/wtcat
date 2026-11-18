# How work happens here, and why

This page explains the development process this repository establishes. The process and the Common Access Token
validator matter equally. The validator is small enough that the process can be seen clearly at work, and the
process is held to the standard of producing a validator worth using. A process that only produces a toy has not
proved anything.

## The problem the process answers

Coding agents raise the rate at which code gets written. They do not, on their own, raise the rate at which
correct software reaches the people who use it. Amazon's published account of its highest-performing teams makes
the same point from the other side: of more than 50 teams studied, the ones that adopted new practices along with
new tools outperformed the ones that added AI to an unchanged workflow ([AWS, 2026-06-10][frontier]). Joe
Magerramov, writing about his own team, puts the arithmetic plainly: if commits go up tenfold, problematic commits
have to go down tenfold or production breaks more often, not less ([Magerramov, 2025-10-19][calculus]).

Both sources are Amazon's own accounts of Amazon's own teams, and AWS sells the tools involved. They are useful as
descriptions of practice, not as proof of any particular speedup.

So the process here spends its effort where agents do not help by default: on saying precisely what correct
means, on catching mistakes before they are committed, and on keeping a fast contributor from making a red build
green the easy way.

## A unit of work, start to finish

1. **Decide.** Any choice with lasting cost becomes a decision record in [docs/decisions/](../decisions/), proposed
   by whoever finds it and accepted or changed by the owner.
2. **State the intent.** The behaviour is written as statements a test can check, before any implementation.
3. **Protect what must hold.** The tests that encode the promise go into the protected set (see below), approved
   by the owner.
4. **Write the task.** A small, well-scoped task with its failing tests already in place.
5. **Implement.** Usually an agent. The job is to make the task's tests pass without widening the task.
6. **Gate.** Every test runs. The census gate confirms every protected test still exists, ran and passed.
7. **Review and commit.** The owner reviews interfaces, behaviour and architecture rather than style, and the
   commit carries her name.

## The practices, and where they come from

| Practice | Source |
|---|---|
| Build context before code: steering file, conventions, decision records | AWS frontier teams: "invest in agent context", "slow down to speed up" |
| Make intent explicit before code is written | AWS frontier teams |
| Keep a backlog of small tasks with clear outcomes, run in parallel | AWS frontier teams: "feed agents instead of babysitting them" |
| Test early and locally, with realistic fakes of dependencies | AWS frontier teams: "shift testing left"; Magerramov's "wind tunnel" tests |
| Protected tests and a census gate | This project; see [decision 0003](../decisions/0003-protected-tests.md) |
| Fuzz every parser of untrusted input | This project; see [decision 0011](../decisions/0011-fuzzing.md) |
| Test the tests by planting faults | This project; see [decision 0013](../decisions/0013-mutation-testing.md) |
| Model-check designs with shared state before building them (an experiment) | This project; see [decision 0032](../decisions/0032-model-checking-designs.md) |
| Predictions committed before measurements | This project's owner, carried over from earlier work |
| Every commit has a human who stands behind it | Magerramov |

## Protected tests

The quickest way to turn a red build green is to remove whatever makes it red: delete the failing test, skip it,
or weaken its assertion. A fast contributor under pressure to finish will find that route, whether it is a person
or an agent. So a small set of tests is protected. They encode what the validator promises, they live apart from
ordinary tests, and a gate fails the build if any of them is missing, skipped, altered or failing. Changing one is
possible, but only deliberately, by the owner, with a decision record saying why. The mechanism is proposed in
[decision 0003](../decisions/0003-protected-tests.md).

Ordinary tests are different. They change freely through normal review as the code changes.

## Testing the tests

A passing suite says little about how much it checks. Two practices measure that directly, and between them they
found most of this project's real defects, each recorded in [the measurements](../reference/measurements.md).

- **Fuzzing** feeds a parser millions of generated inputs, looking for a crash, or for an input that breaks a
  property the code promises, such as a normalized URI normalizing to itself. Here it found a date whose fraction
  could reach 1, and hosts that parsed differently a second time ([decision 0011](../decisions/0011-fuzzing.md)).
- **Mutation testing** plants one small fault at a time, such as a flipped comparison or a deleted check, and runs
  the tests against each. A fault the tests do not notice, a *survivor*, is either equivalent, unable to change
  behaviour, or a gap. Each gap gets a test, and each equivalent survivor is recorded with its reason. A tool,
  Gremlins, does this across a whole package ([decision 0013](../decisions/0013-mutation-testing.md)). For a change
  in progress, a dozen faults planted by hand in the lines just written is quicker, and finds the same kinds of
  gap: a test that passes for a reason other than the one it names, or a rule nothing tests at all.

Neither replaces outside vectors. A surviving mutant shows that a test misses a change; a killed one shows only that
the test notices it, not that the code was right to begin with.

Gremlins starts thousands of short-lived test processes and loads every core for minutes. Run it where an
interruption costs nothing, such as a build server, rather than on a machine doing other work. In CI it is a gate:
each package has an efficacy threshold, and a run below it fails
([decision 0024](../decisions/0024-mutation-testing-in-ci.md)).

## Checking designs before code (an experiment)

Tests check code, one run at a time. A design where several parties share state, such as relays sharing which
connection a token is bound to, can fail only in rare orderings that no test happens to run. For such designs the
project is trying TLA+: a small model of the design, with the properties it must keep, checked by TLC across every
ordering up to a bound. Each model lives in `specs/`, its configurations and their predicted outcomes go in the
measurements before TLC runs, and its properties become Go property tests where the code exists, so the model and
the code cannot quietly drift apart. Whether this earns its place is judged after the first two models
([decision 0032](../decisions/0032-model-checking-designs.md)).

## Roles

- **The owner** (Terra Howard) decides forks, owns the protected tests, reviews and commits.
- **Agents** draft, implement tasks, propose decisions, and report failures as findings. They never change
  protected tests, the manifest or the gate.

## Measuring the process itself

Commit counts measure output, not value. The measures here, each with its prediction committed before it is
taken:

- the protected suite green at every commit;
- compile-and-fix rounds per task;
- the share of planted faults the tests catch, and what each one they miss turns out to be;
- time per task;
- defects found after a commit, and which step should have caught them.

## Sources

- [AWS, "How frontier teams are reinventing AI-native development", 2026-06-10][frontier]
- [Joe Magerramov, "The New Calculus of AI-based Coding", 2025-10-19][calculus]
- [AWS, "AI-Driven Development Life Cycle: Reimagining Software Engineering", 2025-07-31][aidlc]

[frontier]: https://aws.amazon.com/blogs/machine-learning/how-frontier-teams-are-reinventing-ai-native-development/
[calculus]: https://blog.joemag.dev/2025/10/the-new-calculus-of-ai-based-coding.html
[aidlc]: https://aws.amazon.com/blogs/devops/ai-driven-development-life-cycle/
