# AGENTS.md

Read this before changing anything. It applies to every coding agent working in this repository, and to humans
too where it makes sense.

## What this repository is

A Go validator for the Common Access Token (CTA-5007), and the development process it is built with. Both are
deliverables of equal weight. The process is explained in
[docs/explanation/process.md](docs/explanation/process.md). Read it once per session.

## Rules that do not bend

1. **Protected tests are not yours to change.** Tests under `conformance/` and listed in `conformance/MANIFEST`
   define what the validator promises. Never edit, skip, disable, rename or delete one, and never change the
   manifest or the gate that checks them. If a protected test fails, stop and report the failure. A red protected
   test is a result, not an obstacle. Only the owner changes protected tests, through a decision record.
2. **Work from a written task.** Each task names its goal and arrives with failing tests. Make those tests pass
   without widening the task. If the task is unclear or wrong, say so instead of guessing.
3. **Forks go to the owner.** A choice with lasting cost (a dependency, an API shape, a behaviour the spec leaves
   open) becomes a decision record in `docs/decisions/` with status `proposed`. Do not pick silently.
4. **Do not guess the specification.** The authoritative text is CTA-5007-B. Where a behaviour is not established
   by a source listed in `docs/decisions/0002-spec-sources.md`, mark it `spec-needed` and stop.
5. **Public, attributed material only.** This repository will be public. Use public specifications and
   open-source material under compatible licences, with attribution. Do not copy code from other CAT
   implementations. Tokens they produce may be used as test fixtures, with their source and licence recorded next
   to the fixture.
6. **Dependencies need a decision record.** Standard library first.
7. **Predictions before measurements.** Before a benchmark or other measurement, commit the predicted result. Then
   measure and record both.

## Conventions

- Go 1.26. Code is `gofmt`-clean and passes `go vet ./...`.
- Each source file's tests go in the test file of the same name: `mac0.go` is tested in `mac0_test.go`, and tests
  that need the package's internals go in `mac0_internal_test.go`. Fuzz targets sit with their subject's tests.
  Helpers shared across a package's tests go in `helpers_test.go`. A package's `doc.go` maps its files; update it
  when you add one.
- Small commits, one task each, with a message that says what changed and why. Commits are authored by Terra
  Howard; agent-assisted commits add a `Co-Authored-By` trailer.
- Documentation follows Diátaxis. No em-dashes anywhere in this repository.

## Commands

- `go test ./...` runs every test.
- `go run ./cmd/census` is the gate for protected tests. Green means every protected test exists, ran, passed and
  is unchanged. Red lists every reason. Run it before every commit.
