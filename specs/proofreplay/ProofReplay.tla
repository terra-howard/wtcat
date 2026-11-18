------------------------------ MODULE ProofReplay ------------------------------
(***************************************************************************)
(* Replay detection for MOQT DPoP proofs (decision 0038).                  *)
(*                                                                         *)
(* draft-ietf-moq-c4m has a relay accept a proof whose iat is within W     *)
(* seconds of now, either way, and, when catdpop asks for it, refuse a     *)
(* proof whose cti it accepted before within that window. A store cannot   *)
(* keep every cti forever, so it forgets each after a while. The model     *)
(* asks how long is long enough: W from when the proof was first seen, or  *)
(* until its iat plus W. A client chooses its proof's iat, so it can be in *)
(* the future, by up to W.                                                 *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS W,          \* the freshness window, in seconds
          MaxTime,    \* how far the model runs
          Retention   \* "seen": keep a cti until first seen + W; "iat": until iat + W

VARIABLES now,       \* the relay's clock
          iat,       \* the one proof's iat, chosen by the client
          until,     \* when the store forgets the proof's cti, or 0 if it holds none
          accepts    \* how many times the relay has accepted the proof

vars == <<now, iat, until, accepts>>

Fresh == now <= iat + W /\ iat <= now + W

Init ==
    /\ now = 1
    /\ iat \in 1..MaxTime
    /\ until = 0
    /\ accepts = 0

\* The proof is presented: accepted if fresh and its cti is not held, and then recorded.
Present ==
    /\ Fresh
    /\ until = 0
    /\ accepts' = accepts + 1
    /\ until' = IF Retention = "seen" THEN now + W ELSE iat + W
    /\ UNCHANGED <<now, iat>>

\* Time passes, and the store forgets a cti whose time is up.
Tick ==
    /\ now < MaxTime
    /\ now' = now + 1
    /\ until' = IF until # 0 /\ now + 1 > until THEN 0 ELSE until
    /\ UNCHANGED <<iat, accepts>>

Next == Present \/ Tick

Spec == Init /\ [][Next]_vars

\* The property the draft asks for: one proof is accepted once.
AcceptedOnce == accepts <= 1
==================================================================================
