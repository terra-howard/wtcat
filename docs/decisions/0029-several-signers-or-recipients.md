# 0029. Messages with several signers or recipients

- **Status:** accepted, 2026-11-17
- **Decided by:** Claude, under Terra Howard's delegation (2026-11-17, after publication).
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-17).

## Question asked

RFC 8392 allows a CWT to be a COSE_Sign (tag 98), signed by several signers, or a COSE_Mac (tag 97), MACed for
several recipients. CTA-5007-B section 4.3.1.1 builds on RFC 8392 section 7, and the design explanation called these
the most likely next addition. No CAT example or known issuer uses them. Should `cwt` verify them, and with what
policy?

## Reasoning

- **Build them, because the outside vectors exist.** The COSE working group's examples, already pinned at commit
  `53c9d63` (decision 0009), include `sign-tests` and `mac-tests`, with passing and failing messages, keys and the
  exact bytes signed or MACed. That meets decision 0008's rule that verification does not ship without an outside
  check.
- **Tagged only.** An untagged COSE_Sign or COSE_Mac can be told apart from the single-party forms by its shape,
  but nothing needs that. Requiring tags 98 and 97 keeps the parser from guessing.
- **The policy for several signers.** RFC 9052 leaves the policy to the application. A recipient knows some
  signers' keys and not others, so:
  - a signature whose `kid` the key lookup does not know is skipped;
  - **a signature whose key is known must verify**, or the whole message is refused, because a known key with a
    bad signature is evidence of tampering, not a signer to ignore;
  - at least one signature must verify, or the message is refused.

  The signer whose signature verified is reported, so a caller that binds keys to issuers can check `iss` against
  it, as `cat` does.
- **Several recipients: only direct keys.** In a COSE_Mac, each recipient structure says how that recipient gets the
  MAC key. CAT's MAC keys are shared secrets, so the case that matters is the direct method (`alg` -6), where the
  recipient's `kid` names the shared key itself. Key wrapping and key agreement need key material this package
  does not handle, and are refused as unsupported. The same skip, must-verify and at-least-one rules apply, by
  recipient.
- **Algorithms are those already supported:** HMAC 256/64 and 256/256 for MACs, ES256 and PS256 for signatures, each
  key bound to one algorithm (decision 0015). An algorithm in a signer's or the body's protected header must name
  the key's algorithm, as for the single-party forms.
- **Headers.** The body's headers and each signer's or recipient's headers follow decision 0008. A `kid` belongs
  in the signer or recipient headers, where RFC 9052 puts it. A `kid` in the body is refused, since it would be
  ambiguous which signer it names.

## Decision

1. `cwt.VerifyMessage` accepts tagged COSE_Sign and COSE_Mac messages as well, under the rules above. Its
   `Message.KID` reports the signer or recipient whose MAC or signature verified.
2. Tests use the COSE working group's `sign-tests` and `mac-tests` from the pinned commit, copied unchanged beside
   the existing vectors, plus rule tests for the policy: an unknown signer skipped, a known signer with a bad
   signature refusing the message, and no known signer.
3. The design explanation moves "several signers or recipients" out of "Deliberately not supported", and keeps key
   wrapping and key agreement there.
