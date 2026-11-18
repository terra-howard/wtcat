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
(*   DropOnClose: the store forgets a binding when its connection closes   *)
(*           (TRUE), or keeps it until the token expires (FALSE); the      *)
(*           draft asks for the second (decision 0037).                    *)
(***************************************************************************)
EXTENDS FiniteSets, Naturals

CONSTANTS Relays, Tokens, Shared, Atomic, DropOnClose, None

Conns == Relays \X {1, 2}            \* two connections at each relay
RelayOf(c) == c[1]
Parts == IF Shared THEN {"all"} ELSE Relays
Part(r) == IF Shared THEN "all" ELSE r

VARIABLES store,     \* the cti bindings: store[part][token] is a connection or None
          pending,   \* lookups that found no binding and have not written yet
          accepted,  \* every <<token, connection>> a relay has accepted
          live,      \* tokens not yet expired
          closed     \* connections that have ended

vars == <<store, pending, accepted, live, closed>>

TypeOK ==
    /\ store \in [Parts -> [Tokens -> Conns \cup {None}]]
    /\ pending \subseteq Tokens \X Conns
    /\ accepted \subseteq Tokens \X Conns
    /\ live \subseteq Tokens
    /\ closed \subseteq Conns

Init ==
    /\ store = [p \in Parts |-> [t \in Tokens |-> None]]
    /\ pending = {}
    /\ accepted = {}
    /\ live = Tokens
    /\ closed = {}

\* The token is already bound to this connection: accept it again.
PresentBound(t, c) ==
    /\ c \notin closed
    /\ t \in live
    /\ store[Part(RelayOf(c))][t] = c
    /\ accepted' = accepted \cup {<<t, c>>}
    /\ UNCHANGED <<store, pending, live, closed>>

\* Unbound, with an atomic bind-if-unbound: bind and accept in one step.
PresentAtomic(t, c) ==
    /\ Atomic
    /\ c \notin closed
    /\ t \in live
    /\ store[Part(RelayOf(c))][t] = None
    /\ store' = [store EXCEPT ![Part(RelayOf(c))][t] = c]
    /\ accepted' = accepted \cup {<<t, c>>}
    /\ UNCHANGED <<pending, live, closed>>

\* Unbound, without atomicity: the lookup happens now, the write later.
Lookup(t, c) ==
    /\ ~Atomic
    /\ c \notin closed
    /\ t \in live
    /\ store[Part(RelayOf(c))][t] = None
    /\ pending' = pending \cup {<<t, c>>}
    /\ UNCHANGED <<store, accepted, live, closed>>

Bind(t, c) ==
    /\ <<t, c>> \in pending
    /\ store' = [store EXCEPT ![Part(RelayOf(c))][t] = c]
    /\ accepted' = accepted \cup {<<t, c>>}
    /\ pending' = pending \ {<<t, c>>}
    /\ UNCHANGED <<live, closed>>

\* A token bound to another connection is refused, which changes nothing.

\* The token expires; it is never accepted again, so its binding may go.
Expire(t) ==
    /\ t \in live
    /\ live' = live \ {t}
    /\ UNCHANGED <<store, pending, accepted, closed>>

\* A connection ends. A store that drops bindings on close forgets the tokens bound to it.
Close(c) ==
    /\ c \notin closed
    /\ closed' = closed \cup {c}
    /\ store' = IF DropOnClose
                 THEN [p \in Parts |-> [t \in Tokens |-> IF store[p][t] = c THEN None ELSE store[p][t]]]
                 ELSE store
    /\ UNCHANGED <<pending, accepted, live>>

Next ==
    \/ \E t \in Tokens, c \in Conns :
          PresentBound(t, c) \/ PresentAtomic(t, c) \/ Lookup(t, c) \/ Bind(t, c)
    \/ \E t \in Tokens : Expire(t)
    \/ \E c \in Conns : Close(c)

Spec == Init /\ [][Next]_vars

\* The property the draft asks for: a token is accepted on one connection at most.
OneConnection ==
    \A t \in Tokens : Cardinality({c \in Conns : <<t, c>> \in accepted}) <= 1
=============================================================================
