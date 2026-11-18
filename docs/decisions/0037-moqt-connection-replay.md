# 0037. Connection-scoped replay protection for MOQT

- **Status:** accepted, 2026-11-18
- **Decided by:** Claude, under Terra Howard's delegation (the MoQT roadmap, item 4).
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-18).

## Question asked

Decision 0021 made `catreplay` 1 and 2 single use over HTTP: `Validator.Replay` records a `cti` and refuses it the
second time. In MOQT the same token is presented for SETUP and again for every later action on the connection, so
single use would refuse all but the first. How should `cat` handle `catreplay` for MOQT requests?

## What the draft establishes

Paraphrased, draft-ietf-moq-c4m section "Replay Protection without DPoP": for MOQT, `catreplay` 1 means one
connection. A relay binds the token's `cti` to the connection on which it is first accepted, must not refuse the
token again on that connection for having been seen, and must refuse it on any other. A token with `catreplay` 1
and no `cti` or no `exp` must be rejected. After the connection ends, the relay keeps enough state to refuse reuse
for as long as the token could otherwise be accepted. Value 2 is implementation-defined, and 0 or absence means no
replay protection.

## What was checked

`specs/connectionreplay/` (decision 0032) already showed that the binding store must be shared by every relay that
accepts the same tokens, and that binding must be one atomic step (task 63). Task 72 added connections that close:
a store that forgets a binding when its connection closes lets the token in on a new connection, so a binding must
outlive its connection until the token expires.

## Reasoning

- **A separate hook, not a new meaning for `Replay`.** `Replay` answers "seen before?", and a store built for it
  would refuse the second action on a connection. `Validator.BindConnection(cti, connection, until)` binds the `cti`
  to the connection if it is unbound, in one atomic step, and reports whether it is bound to a different one. The
  store must be shared, as `Replay`'s is.
- **`until` is the token's `exp`.** Validation allows no leeway on `exp` (the claims table in the package
  documentation), so the binding can be dropped then, and not before.
- **The connection is named by the caller.** `Connection.ID` is a string unique among every connection whose
  requests the shared store sees. QUIC connection IDs can change during a connection, so the relay's own stable
  identifier is the right one, and a string can be stored anywhere.
- **MOQT requests never call `Replay`,** and HTTP requests never call `BindConnection`, so each store sees one
  meaning.
- **Without the hook, the claim is not enforced,** as for `Replay` (decision 0021). But the token rule does not need
  a store: over MOQT a token with `catreplay` 1 and no `cti` or no `exp` is refused, with or without the hook.
- **With the hook and no connection ID, the token is refused.** The caller asked for enforcement and gave nothing to
  bind to, so accepting would let a missing ID bypass the claim.
- **Value 2 is treated as 1,** including the `cti` and `exp` requirement, as over HTTP, since the draft leaves it to
  the implementation. Values above 2 are treated as 1, as before.
- **Last among the checks,** like `Replay`, so a refused token never binds its `cti`.

## Decision

1. `Connection.ID` names the connection. `Validator.BindConnection`, if set, is called for MOQT requests whose
   token carries a `catreplay` above 0, after every other check, with the `cti`, `Connection.ID` and the token's
   `exp`. A token bound elsewhere is refused with `cat.ErrReplay`.
2. Over MOQT, a token with a `catreplay` above 0 and no `cti` or no `exp` is refused with `cat.ErrReplay`. With
   `BindConnection` set and no `Connection` or an empty `ID`, the token is refused with `cat.ErrReplay`.
3. HTTP requests are unchanged.
