# 0025. Dependency updates

- **Status:** accepted, 2026-11-17
- **Decided by:** Claude, under Terra Howard's delegation (2026-11-17, after publication).
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

## Question asked

The module has two dependencies (decision 0005), and the workflows pin each action to a full commit SHA. Nothing
tells anyone when a dependency or an action has a new release, including a security release. How should updates
arrive?

## Reasoning

- **Pinning without updating only moves the risk.** A pin protects against a moved tag. It also freezes whatever
  flaw the pinned version has, so pins need a way to move on purpose.
- **Dependabot, because it is built into GitHub and needs no new dependency or token.** It opens pull requests,
  and those pass the same `gate` check and code-owner review as any other change. Nothing merges by itself.
- **Weekly, for both `gomod` and `github-actions`, at most five open pull requests each.** Weekly batches the noise
  of a small project. Security advisories arrive outside that schedule through Dependabot security updates, which
  the owner can turn on in the repository settings.
- **Pinned actions stay pinned.** Dependabot updates a SHA pin and the version comment beside it, so the convention
  from `ci.yml` holds.
- **Considered and left out:** Renovate, which does more but is a third-party app with its own permissions; and no
  automation, which leaves the owner to watch releases by hand.

## Consequences

- `.github/dependabot.yml` configures it. Because `.github/` belongs to the owner in `CODEOWNERS`, every update
  needs her review.
- A dependency update can change behaviour the protected tests check. If one turns a protected test red, that is a
  result to report, not a pull request to adjust (AGENTS.md rule 1).
