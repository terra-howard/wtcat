------------------------------ MODULE TokenCache ------------------------------
(***************************************************************************)
(* The MOQT authorization token cache across request streams (decision     *)
(* 0039).                                                                  *)
(*                                                                         *)
(* draft-ietf-moq-transport-22 lets a sender REGISTER a token under an     *)
(* alias, refer to it with USE_ALIAS, and DELETE the alias, each inside a  *)
(* message on some request stream. Each request has its own stream, and a  *)
(* receiver may process streams in any order, so the two sides can disagree *)
(* about the cache. The draft gives senders two rules:                     *)
(*                                                                         *)
(*   UseWaits:    no USE_ALIAS on another stream than the REGISTER's until *)
(*                the REGISTER has been answered;                          *)
(*   DeleteWaits: no DELETE while a USE_ALIAS of the alias is unanswered.  *)
(*                                                                         *)
(* The model asks whether a sender that keeps them can still provoke an    *)
(* error from a receiver that follows the draft: UNKNOWN_AUTH_TOKEN_ALIAS  *)
(* for an alias the sender believes registered, or                         *)
(* DUPLICATE_AUTH_TOKEN_ALIAS, which closes the session. Two further rules *)
(* are candidates:                                                         *)
(*                                                                         *)
(*   ReregisterWaits: no REGISTER of a deleted alias until the DELETE has  *)
(*                    been answered, unless on the DELETE's stream;        *)
(*   DeleteRegWaits:  no DELETE on another stream than the REGISTER's      *)
(*                    until the REGISTER has been answered.                *)
(*                                                                         *)
(* One alias is enough. A response reaches the sender the moment the       *)
(* receiver processes the message, the most permissive timing for a sender *)
(* that waits for responses.                                               *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS Streams, MaxMsgs, UseWaits, DeleteWaits, ReregisterWaits, DeleteRegWaits

VARIABLES queue,      \* queue[s]: the messages sent on stream s, not yet processed
          cache,      \* whether the receiver holds the alias
          believed,   \* whether the sender believes the alias registered
          regStream,  \* the stream of the sender's latest REGISTER
          delStream,  \* the stream of the sender's latest DELETE
          sent,       \* how many messages the sender has sent
          errors      \* the errors the receiver has raised

vars == <<queue, cache, believed, regStream, delStream, sent, errors>>

None == "none"
Unanswered(kind) == {s \in Streams : \E i \in 1..Len(queue[s]) : queue[s][i] = kind}
\* IF, not \/: TLC explores both sides of a disjunction in an action, and queue["none"] does not exist.
Answered(kind, s) == IF s = None THEN TRUE ELSE \A i \in 1..Len(queue[s]) : queue[s][i] # kind

Init ==
    /\ queue = [s \in Streams |-> <<>>]
    /\ cache = FALSE
    /\ believed = FALSE
    /\ regStream = None
    /\ delStream = None
    /\ sent = 0
    /\ errors = {}

Send(s, kind) ==
    /\ sent < MaxMsgs
    /\ queue' = [queue EXCEPT ![s] = Append(@, kind)]
    /\ sent' = sent + 1

SendRegister(s) ==
    /\ ~believed
    /\ ReregisterWaits => (s = delStream \/ Answered("DELETE", delStream))
    /\ Send(s, "REGISTER")
    /\ believed' = TRUE
    /\ regStream' = s
    /\ UNCHANGED <<cache, delStream, errors>>

SendUse(s) ==
    /\ believed
    /\ UseWaits => (s = regStream \/ Answered("REGISTER", regStream))
    /\ Send(s, "USE_ALIAS")
    /\ UNCHANGED <<cache, believed, regStream, delStream, errors>>

SendDelete(s) ==
    /\ believed
    /\ DeleteWaits => Unanswered("USE_ALIAS") = {}
    /\ DeleteRegWaits => (s = regStream \/ Answered("REGISTER", regStream))
    /\ Send(s, "DELETE")
    /\ believed' = FALSE
    /\ delStream' = s
    /\ UNCHANGED <<cache, regStream, errors>>

\* The receiver processes the first message on some stream, as the draft says it must.
Process(s) ==
    /\ queue[s] # <<>>
    /\ LET m == Head(queue[s]) IN
         /\ cache' = CASE m = "REGISTER" -> TRUE
                       [] m = "DELETE"   -> FALSE
                       [] OTHER          -> cache
         /\ errors' = errors \cup
              (IF m = "REGISTER" /\ cache THEN {"DUPLICATE_AUTH_TOKEN_ALIAS"}
               ELSE IF m # "REGISTER" /\ ~cache THEN {"UNKNOWN_AUTH_TOKEN_ALIAS"}
               ELSE {})
    /\ queue' = [queue EXCEPT ![s] = Tail(@)]
    /\ UNCHANGED <<believed, regStream, delStream, sent>>

Next ==
    \/ \E s \in Streams : SendRegister(s) \/ SendUse(s) \/ SendDelete(s) \/ Process(s)

Spec == Init /\ [][Next]_vars

\* A sender that keeps the rules never meets a cache error.
NoCacheErrors == errors = {}
==================================================================================
