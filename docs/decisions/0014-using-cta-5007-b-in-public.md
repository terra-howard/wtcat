# 0014. Using CTA-5007-B in a public repository

- **Status:** proposed, 2026-11-14
- **Decision needed from:** Terra Howard

## Context

The owner obtained CTA-5007-B (April 2025) on 2026-11-14; decision 0002's option A has now happened. The
document is distributed to CTA members. Its section 2 licenses only the CDDL snippets and Annex D, under the ISC
licence with a notice requirement, and section 4.3.1.3 says its CBOR diagnostic-notation examples are not
permissively licensed. Nothing licenses its prose or its encoded example tokens. This repository is headed for
public GitHub.

## Proposal

1. **The PDF and its prose never enter the repository.** Code, comments and decision records cite section numbers
   and state requirements in our own words.
2. **CDDL may be included** where it helps (for example, to check our decoder's shapes), with the ISC notice beside
   it, exactly as the licence asks.
3. **The spec's example tokens and keys stay out of the repository.** Two of its three signing examples are useful
   outside vectors (its HMAC 256/256 and PS256 examples verify against our code), so keep them in a local file the
   repository ignores, read by tests behind a build tag (`go test -tags cta ./...`) that the owner can run. The
   public tests keep using RFC 8392 and the COSE working group's vectors, plus tokens this project builds itself
   from the rules.
4. **Asking CTA** for permission to publish the examples remains possible, and is the owner's call.

## Consequences

- Public CI cannot run the CTA-example tests; they are a local, owner-run check.
- Nothing published depends on members-only text.
