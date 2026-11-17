# 0007. Approve the first protected set

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation for an experiment: at each decision point, ask what an
  expert software engineer would do, record why, and proceed. Pending her review; she may reverse it.
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-17).

## Question asked

What would an expert software engineer do with a proposed protected test set, before any implementation exists?

## Reasoning

An expert locks a test as protected only when its answers come from outside the project, the test cannot be
satisfied by a degenerate implementation, and the set is small enough to stay stable.

- **Outside answers.** Every expected value comes from RFC 8392 Appendix A, copied from the RFC's text by script.
  The RFC's errata were checked; the two reports against A.2.2 concern the key's COSE_Key encoding, and the tests
  use only the raw key value.
- **No degenerate pass.** The tampering cases require `cwt.ErrVerification` specifically. A stub that rejects
  everything fails them, which the current stub demonstrates.
- **Small and stable.** Five tests, all anchored to the RFC. Structure confusion (a COSE_Sign1 token passed to
  `VerifyMac0`), malformed input and header rules are better written first as ordinary tests, then promoted once
  their behaviour has settled. A protected set that churns stops meaning anything.

## Decision

Approve `conformance/rfc8392_test.go` and `conformance/MANIFEST` as written in commit `9899847`.

## If a protected test turns out to be wrong

If the RFC's vectors will not verify against an implementation that is otherwise correct, the expert move is to
stop, prove it with an independent check, and bring it to the owner. Nobody edits the protected test in her
absence.
