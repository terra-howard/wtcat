# 0001. Write the validator in Go

- **Status:** accepted, 2026-11-14
- **Decided by:** Terra Howard

## Context

Java was also considered: it is the owner's deepest language, no Java CAT implementation turned up in a GitHub
search, and it leads toward a later Spring project. Go was the alternative: a single static binary, and only a
learning repository with no stars turned up for Go in the same search.

## Decision

Go, at the owner's preference.

## Consequences

- The census gate can read `go test -json` output, whose event actions (`run`, `pass`, `fail`, `skip` and others)
  are documented by `go doc cmd/test2json`.
- CBOR and COSE support will need either a dependency or our own code. Each dependency gets its own decision
  record.
