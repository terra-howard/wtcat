# 0009. Outside vectors from the COSE working group

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation for an experiment (see decision 0007). Pending her
  review; she may reverse it.
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-17).

## Question asked

RFC 8392's examples cover HMAC 256/64 and ES256 only. HMAC 256/256, the most common CAT algorithm, and PS256 have
no outside vector here. Decision 0008 says cryptographic verification does not ship without one. What would an
expert do?

## Reasoning

Look for an authoritative public source before either shipping untested or cutting scope. The COSE working
group's examples repository, <https://github.com/cose-wg/Examples>, is that source: written by the people who
wrote COSE, released under the Unlicense, and including intermediate values (the exact bytes that were MACed or
signed), which test a structure step by step rather than only end to end.

## Decision

1. Copy the vectors used, unchanged, into `cwt/testdata/cose-wg/`, pinned to commit
   `53c9d634333bb4f529d78f5980fffa2667ee2c12`, with the licence and a source note.
2. **HMAC 256/256:** `mac0-tests/HMac-01.json` checks COSE_Mac0 verification end to end, and its `ToMac_hex`
   intermediate checks the MAC structure byte for byte. Its payload is plain text, not a claims set, so these
   tests call the package's internal COSE layer, beneath `VerifyMac0`.
3. **Rejections:** `mac-fail-01`, `-02`, `-03`, `-04`, `-06` and `-07` must all be rejected. Each test names the
   error our rules give.
4. **A deliberate divergence.** `mac0-tests/mac-pass-01.json` and `sign1-tests/sign-pass-01.json` carry `alg` in
   the unprotected header and expect to pass. Under decision 0008 rule 2 they are rejected, and that stays. An
   unprotected `alg` lets an attacker relabel an HMAC 256/256 token as HMAC 256/64 and cut its tag to the first 8
   bytes, which is exactly a valid 256/64 tag for the same message, quietly lowering the token's strength. The
   tests assert the rejection and say why.
5. **PS256:** `rsa-pss-examples/rsa-pss-01.json` is a multi-signer COSE_Sign, not COSE_Sign1, but it exposes the
   exact bytes signed (`ToBeSign_hex`) and the RSA public key. That checks the PS256 primitive (RSASSA-PSS with
   SHA-256 and MGF1 with SHA-256) against an outside answer, while A.3 checks the COSE_Sign1 envelope. That meets
   decision 0008's condition, so PS256 comes back as its own task, with its own prediction committed first.
6. **COSE_Sign1, added in task 3:** `sign1-tests/sign-pass-03.json` (untagged ES256) verifies end to end and its
   `ToBeSign_hex` checks the signature structure byte for byte; `sign-fail-01`, `-02`, `-03`, `-04`, `-06` and
   `-07` are rejected; `sign-pass-01` is the same deliberate divergence as `mac-pass-01`. `sign-pass-02` is left
   out: it uses external authenticated data, which this API does not take.
7. **Ordinary tests, not protected ones.** Adding to the protected set changes the manifest, which is the owner's
   to change. These vectors are proposed for promotion when she reviews this experiment.
