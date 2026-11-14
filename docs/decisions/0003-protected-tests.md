# 0003. Protected tests and the census gate

- **Status:** accepted, 2026-11-14
- **Decided by:** Terra Howard

## Context

A build can be turned green by removing what makes it red. The tests that encode what the validator promises
need protection that does not depend on every contributor resisting that shortcut. Ordinary tests stay free to
change through normal review.

## Decision

1. **Where they live.** Protected tests go in a `conformance/` package and nowhere else.
2. **The manifest.** `conformance/MANIFEST` lists each protected test by its full `go test` name, with the SHA-256
   of the file it lives in.
3. **The census gate.** A small tool, `cmd/census`, runs `go test -json ./conformance/...` and fails unless:
   - every manifest entry appears in the event stream and ends with action `pass`;
   - no protected test ends with `skip` or `fail`;
   - the number of protected tests that passed equals the number in the manifest;
   - every file hash matches the manifest.

   So deleting, skipping, renaming or editing a protected test all fail the gate.
4. **Deliberate change.** A protected test changes together with its manifest entry, in one commit that cites a
   decision record.
5. **Protect the gate too.** Once the repository is on GitHub, a `CODEOWNERS` file names the owner for
   `conformance/`, `cmd/census/`, the CI workflow and any build configuration that selects tests, and branch
   protection requires the owner's review. Without that, the shortcut moves from removing a test to removing the
   gate.
6. **Agents.** [AGENTS.md](../../AGENTS.md) forbids agents to touch protected paths. A tool-level block in the
   agent's own permission settings is the owner's to add.
7. **Tests that pass without checking much.** Hashes catch edits. Mutation testing on the code the protected
   tests cover catches tests that were weak from the start. The tool is a later decision.
8. **Until the remote exists,** the gate runs locally as a command, and later in CI on every commit.
9. **Line endings.** This machine's Git converts LF to CRLF on checkout, and a hash of a CRLF file differs from a
   hash of the same file with LF. The census hashes content with line endings normalised to LF, and a
   `.gitattributes` with `* text=auto eol=lf` keeps working copies identical across platforms. That file was
   added when this decision was accepted.

## First protected set

RFC 8392 Appendix A's worked examples: the claims set must decode to the listed claims, and the signed, MACed and
encrypted examples must verify or decrypt with the listed keys. These were written by the RFC's authors, not by
anyone on this project, which is the point.

## Consequences

- One small Go tool to build and maintain.
- Protected tests become slower to change on purpose.

## Implementation notes, 2026-11-14

Prepared under the owner's delegation for the experiment (decision 0007), pending her review: the workflow is in
`.github/workflows/ci.yml` and the owners file in `.github/CODEOWNERS`. `CODEOWNERS` also covers
`internal/census/` (the census logic, beside its command) and `AGENTS.md` (the rules agents follow), both of which
the gate depends on. Neither file does anything until the repository is on GitHub and branch protection requires
code-owner review.
