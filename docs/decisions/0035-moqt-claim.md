# 0035. The moqt claim

- **Status:** accepted, 2026-11-18
- **Decided by:** Claude, under Terra Howard's delegation (the MoQT roadmap, item 2).
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

## Question asked

draft-ietf-moq-c4m defines a `moqt` claim that says which MOQT actions a token authorizes, on which track namespaces
and track names. A MOQT relay checks it at SETUP and for every action. How should `cat` decode and enforce it, given
that the claim has no assigned key yet?

## What the draft establishes

Paraphrased from the editor's copy `55d8a2e8`, section "moqt claim":

- The value is a map. Key 0 holds an array of one or more scopes. Any other key is reserved, and a recipient must
  treat a claim set holding one as not acceptable (fail closed).
- A scope is `[actions, ?[namespace matches], ?track match]`. Actions are integers: SETUP 1, PUBLISH_NAMESPACE 2,
  SUBSCRIBE_NAMESPACE 3, SUBSCRIBE 4, REQUEST_UPDATE 5, PUBLISH 6, FETCH 7, TRACK_STATUS 8, SUBSCRIBE_TRACKS 9.
- A match is a byte string (exact) or `[1 prefix | 2 suffix, bytes]`, compared bytewise with no normalization. The
  first namespace match applies to the first namespace field, and so on. A final nil means the namespace has exactly
  that many fields. Without it, longer namespaces whose leading fields match are included. nil anywhere but last
  is invalid.
- Without namespace matches, a scope covers every namespace. Without a track match, it covers every track name.
- Actions not listed are not authorized, and with a token present, every MOQT action is blocked unless a scope
  allows it. A request is allowed when any scope allows it.

## Reasoning

- **The claim key is configurable.** IANA has not assigned one. The draft's vectors use the private-use key -65537,
  so that is the default (`cat.MOQTClaimKey`), and a recipient can set `Validator.MOQTClaimKey` to follow a
  deployment or, later, the assigned key.
- **A request type for MOQT actions.** `cat.Request` describes HTTP requests. MOQT actions get their own type,
  `cat.MOQTAction`: the action code, the Track Namespace fields and the Track Name. A request carries one in
  `Request.MOQT`, and it is nil for HTTP.
- **Enforcement follows the draft.** For a MOQT request, a token without the claim authorizes nothing, and one with
  it authorizes the action only if a scope does. For an HTTP request, the claim says nothing, since it scopes MOQT
  actions only, and it is decoded and checked for form but not enforced.
- **A scope with a track match needs a track name.** A request for an action without a Track Name, such as SETUP
  or SUBSCRIBE_NAMESPACE, matches only scopes without a track match. A scope with namespace matches needs at least
  as many namespace fields as it has matches.
- **Unknown action codes are allowed in a scope and simply never match.** The draft can add actions, and refusing
  a token because it mentions one would break forward compatibility. That is unlike unknown map keys, which the
  draft says to refuse.
- **`moqt-reval` is refused as unsupported until roadmap item 3.** The draft requires a recipient that cannot
  revalidate to reject a token carrying it. Its key is also configurable, defaulting to the vectors' -65538.
- **Tags.** CTA-5007-B section 4.5 forbids tags on claim values, and the claim's CDDL uses none, so any tag in the
  value is malformed.

## Decision

1. `cat` decodes the claim at `Validator.MOQTClaimKey` (default -65537) under the rules above, with violations
   malformed and an unknown map key unacceptable.
2. `Request.MOQT`, when set, is authorized against the claim's scopes. Without the claim, or with no scope allowing
   it, the request is refused with `cat.ErrMOQT`, which wraps `ErrUnacceptable`.
3. A token carrying `moqt-reval` (at `Validator.MOQTRevalKey`, default -65538) is refused as unsupported until its
   own decision.
4. Tests use the draft's "MOQT Authorization Scopes" vectors, each of whose authorization tests becomes a
   `Request.MOQT`, plus rule tests.
