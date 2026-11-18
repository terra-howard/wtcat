# 0040. Protecting the COSE working group's vectors

- **Status:** accepted, 2026-11-18
- **Decided by:** Terra Howard, that the COSE working group's vectors for several signers or recipients and for
  COSE_Encrypt0 join the protected set (*"We can do it now."*, after the candidates below). Its shape was chosen by
  Claude under her delegation.
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

## Question asked

Which of the tests added since decision 0003 encode promises firmly enough to be protected?

## Reasoning

- **These vectors come from outside and do not move.** They are pinned to a commit of the working group's
  repository (decision 0009), and the only good reason to change what they expect would be a change to COSE itself,
  which is the bar a protected test should set.
- **Only where this project agrees with the working group.** Vectors the group marks as passing and this project
  refuses on purpose (decisions 0008, 0009 and 0029) stay in the ordinary tests, since those refusals are this
  project's own choices and may be revisited. A failing vector is checked for being refused, not for its error kind,
  which is also this project's classification.
- **The vector files are pinned too.** MANIFEST pins a test file's hash, but these tests read their vectors from
  `cwt/testdata/cose-wg/`. Each vector's SHA-256 is written into the protected file, so an edited vector fails the
  tests; changing a vector at a new commit means changing the protected file, with a decision record.
- **Considered and left for later:** draft-ietf-moq-c4m's vectors, until the draft settles, since its claim keys are
  still placeholders; and the RFC 9679 and RFC 8037 thumbprint values, which the public API cannot reach without a
  private key or an exported thumbprint function.

## Decision

`conformance/cosewg_test.go` holds four tests over 26 vectors: COSE_Sign and COSE_Mac messages that verify and
messages that must be refused, and COSE_Encrypt0 messages that decrypt and messages that must be refused. They join
MANIFEST.
