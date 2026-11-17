# 0014. Using CTA-5007-B in a public repository

- **Status:** accepted, 2026-11-14 (proposed the same day)
- **Decided by:** Claude, under Terra Howard's delegation; pending her review. She may reverse it.
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-17).

## Context

The owner obtained CTA-5007-B (April 2025) on 2026-11-14, as a free ($0) purchase from CTA's shop; no membership
was needed (an earlier note in decision 0002 said otherwise). CTA has offered its standards library free since
2018 ([press release][free]). Free to download is not free to republish, though: the [terms of use][terms] on CTA's CES
site say its content may not be used without written permission except as the terms allow, and point copyright
questions to copyright@cta.tech. The standards shop's own terms could not be read (its pages refused automated
requests). Within the document, section 2 licenses only the CDDL snippets and Annex D, under the ISC
licence with a notice requirement, and section 4.3.1.3 says its CBOR diagnostic-notation examples are not
permissively licensed. Nothing licenses its prose or its encoded example tokens. This repository is headed for
public GitHub.

## Proposal

1. **The PDF and its prose never enter the repository.** Code, comments and decision records cite section numbers
   and state requirements in our own words, and the README tells readers where to download the document free.
2. **CDDL may be included** where it helps (for example, to check our decoder's shapes), with the ISC notice beside
   it, exactly as the licence asks.
3. **The spec's example tokens and keys stay out of the repository, but anyone can reproduce the tests.** Two of
   its three signing examples are useful outside vectors (its HMAC 256/256 and PS256 examples verify against our
   code). Commit a small extraction program, our own code, that reads the text of a contributor's own downloaded
   copy and writes the examples to a local file the repository ignores; tests behind a build tag
   (`go test -tags cta ./...`) read that file. The public tests keep using RFC 8392 and the COSE working group's
   vectors, plus tokens this project builds itself from the rules.
4. **Asking CTA** (copyright@cta.tech) for permission to publish the examples remains possible, and is the owner's
   call.

## Question asked

What would an expert software engineer do with a standard that is free to read but not licensed for
republication, in a repository that will be public?

## Reasoning

- **Treat the licence as written, not as hoped.** An expert does not stretch "free to download" into "free to
  copy". The only grant in the document covers the CDDL and Annex D, so those are the only parts that may appear
  here, with the notice the grant requires. Everything else is cited by section and restated in our own words,
  which is how open-source implementations of paywalled or restricted standards normally work.
- **Keep outside vectors without publishing them.** Independent test vectors are the most valuable tests a
  verifier has; decision 0008 refused to ship PS256 without one. Two of the specification's examples verify
  against this code, so throwing them away would cost real assurance. Reading them from each contributor's own
  copy keeps that assurance and publishes nothing.
- **Quote nothing, even to find things.** The first extraction, done by hand on 2026-11-14, located examples by
  short phrases of the document's prose. Committed code should not carry even those. The extraction program finds
  examples by structure instead: the running header and page numbers that interrupt the text, the CBOR prefixes a
  COSE_Mac0 or COSE_Sign1 token must begin with, PEM armour (RFC 7468, not CTA's text), and the shape of a
  base64-encoded 256-bit key. It then confirms each candidate by verifying a token with it, so a wrong extraction
  fails loudly instead of producing a wrong vector.
- **A requested test that cannot run fails; it does not skip.** Someone who runs `go test -tags cta` has asked for
  those tests. If the local file is missing, the tests fail with instructions for producing it. A silent skip is a
  green build that checked nothing, which is the failure decision 0003 exists to prevent.
- **Leave out a vector that is known to be broken.** The specification's ES256 examples do not verify with its
  published key (decision 0015). Tests built around a broken vector either encode the error as expected behaviour
  or fail forever; neither helps. ES256 keeps relying on RFC 8392 and the COSE working group's vectors until a
  corrected example exists.
- **Contacting CTA stays with the owner.** Writing to a standards body on her behalf is a commitment that binds
  her, so neither the copyright question nor the apparent errata are sent from here.

## Decision

Accept the proposal, with four refinements:

1. The extraction program locates examples only by structure (running header and page numbers, COSE prefixes,
   PEM armour, key shape) and confirms each by verification. It contains no prose from the document.
2. Its input is the output of `pdftotext` (without `-layout`) run on the contributor's own copy, so the
   repository needs no PDF library; its output goes to a path listed in `.gitignore`.
3. Tests behind the `cta` build tag fail, with instructions, when that output is missing.
4. The ES256 examples are excluded, with the reason recorded beside the tests.

## Consequences

- Public CI cannot run the CTA-example tests; they run locally for anyone who has downloaded the document.
- Nothing published reproduces CTA's text.
- The extraction program depends on how `pdftotext` lays out this edition. A new edition may need it adjusted;
  verification of each candidate makes that failure visible.

[free]: https://www.cta.tech/press-releases/ctas-entire-library-of-industry-standards-now-free-to-everyone
[terms]: https://www.ces.tech/about-ces/terms-of-use/
