---------------------------- MODULE ConnectionReplay ----------------------------
(***************************************************************************)
(* Connection-scoped replay protection for CAT over MOQT (decision 0032).  *)
(*                                                                         *)
(* draft-ietf-moq-c4m reads catreplay 1 as "one connection": a relay binds *)
(* a token's cti to the first connection that presents it, accepts the     *)
(* token again on that connection, and refuses it on any other. This       *)
(* model asks what the binding store must be for that to hold when several *)
(* relays accept the same tokens.                                          *)
(*                                                                         *)
(*   Shared: all relays use one store (TRUE) or each keeps its own (FALSE). *)
(*   Atomic: "bind if unbound" is one step (TRUE), or a lookup followed by *)
(*           a separate write (FALSE), as a cache read then set would be.  *)
(***************************************************************************)
EXTENDS FiniteSets, Naturals

CONSTANTS Relays, Tokens, Shared, Atomic, None

Conns == Relays \X {1, 2}            \* two connections at each relay
RelayOf(c) == c[1]
Parts == IF Shared THEN {"all"} ELSE Relays
Part(r) == IF Shared THEN "all" ELSE r

VARIABLES store,     \* the cti bindings: store[part][token] is a connection or None
          pending,   \* lookups that found no binding and have not written yet
          accepted,  \* every <<token, connection>> a relay has accepted
          live       \* tokens not yet expired

vars == <<store, pending, accepted, live>>

TypeOK ==
    /\ store \in [Parts -> [Tokens -> Conns \cup {None}]]
    /\ pending \subseteq Tokens \X Conns
    /\ accepted \subseteq Tokens \X Conns
    /\ live \subseteq Tokens

Init ==
    /\ store = [p \in Parts |-> [t \in Tokens |-> None]]
    /\ pending = {}
    /\ accepted = {}
    /\ live = Tokens

\* The token is already bound to this connection: accept it again.
PresentBound(t, c) ==
    /\ t \in live
    /\ store[Part(RelayOf(c))][t] = c
    /\ accepted' = accepted \cup {<<t, c>>}
    /\ UNCHANGED <<store, pending, live>>

\* Unbound, with an atomic bind-if-unbound: bind and accept in one step.
PresentAtomic(t, c) ==
    /\ Atomic
    /\ t \in live
    /\ store[Part(RelayOf(c))][t] = None
    /\ store' = [store EXCEPT ![Part(RelayOf(c))][t] = c]
    /\ accepted' = accepted \cup {<<t, c>>}
    /\ UNCHANGED <<pending, live>>

\* Unbound, without atomicity: the lookup happens now, the write later.
Lookup(t, c) ==
    /\ ~Atomic
    /\ t \in live
    /\ store[Part(RelayOf(c))][t] = None
    /\ pending' = pending \cup {<<t, c>>}
    /\ UNCHANGED <<store, accepted, live>>

Bind(t, c) ==
    /\ <<t, c>> \in pending
    /\ store' = [store EXCEPT ![Part(RelayOf(c))][t] = c]
    /\ accepted' = accepted \cup {<<t, c>>}
    /\ pending' = pending \ {<<t, c>>}
    /\ UNCHANGED live

\* A token bound to another connection is refused, which changes nothing.

\* The token expires; it is never accepted again, so its binding may go.
Expire(t) ==
    /\ t \in live
    /\ live' = live \ {t}
    /\ UNCHANGED <<store, pending, accepted>>

Next ==
    \/ \E t \in Tokens, c \in Conns :
          PresentBound(t, c) \/ PresentAtomic(t, c) \/ Lookup(t, c) \/ Bind(t, c)
    \/ \E t \in Tokens : Expire(t)

Spec == Init /\ [][Next]_vars

\* The property the draft asks for: a token is accepted on one connection at most.
OneConnection ==
    \A t \in Tokens : Cardinality({c \in Conns : <<t, c>> \in accepted}) <= 1
=============================================================================
