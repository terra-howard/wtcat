# 0010. Checking the validity window

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation for an experiment (see decision 0007). Pending her
  review; she may reverse it.
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

## Question asked

Authenticity is checked (decisions 0006 and 0008); validity in time is not. What would an expert add next, and
how?

## Reasoning

A verifier that accepts expired tokens is not usable, so this comes before CAT's own claims, most of which are
`spec-needed` anyway. RFC 8392 gives `exp`, `nbf` and `iat` the meaning of RFC 7519 Sections 4.1.4 to 4.1.6:

- `exp`: "the current date/time MUST be before the expiration date/time".
- `nbf`: "the current date/time MUST be after or equal to the not-before date/time".
- Both: "Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock
  skew."
- `iat` carries no acceptance rule. All three are optional.

The expert choices around those rules: take the time and the leeway as arguments rather than reading the clock
inside, so tests are exact and callers control skew; make the boundaries exact and tested; and never let
arithmetic near the limits of `int64` wrap round into a wrong answer.

## Decision

```go
var ErrExpired error     // now is at or after exp, after leeway
var ErrNotYetValid error // now is before nbf, after leeway

func (c *Claims) CheckTime(now time.Time, leeway time.Duration) error
```

- Expired when `now`, in whole seconds, is at or after `exp + leeway`. Not yet valid when `now` is before
  `nbf - leeway`. Leeway counts in whole seconds, rounded down, matching the integer dates.
- An absent claim is not checked. Whether a CAT must carry `exp` is `spec-needed`; requiring it is a policy
  option for the `Verifier` recorded in decision 0006.
- `iat` is not checked.
- A negative leeway is a programming error and returns an error rather than silently tightening the window.
- Sums that would overflow are treated as "never expires" or "always valid from the start" for that bound, which
  is what the arithmetic means once the limits are reached.
