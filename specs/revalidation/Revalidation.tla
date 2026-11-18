------------------------------ MODULE Revalidation ------------------------------
(***************************************************************************)
(* Revalidating a token on a long MOQT stream (decision 0036).             *)
(*                                                                         *)
(* draft-ietf-moq-c4m's moqt-reval claim says a relay must revalidate the  *)
(* token of an ongoing stream at least every Reval seconds, and stop the   *)
(* stream once the token is no longer acceptable. Time is discrete. The    *)
(* token stops being acceptable at Exp, or earlier if it is revoked. The   *)
(* model asks how late a stream can run on an unacceptable token, under a  *)
(* relay that revalidates every Interval seconds from the last check.      *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Reval,     \* the token's moqt-reval, in seconds (positive)
          Interval,  \* how often the relay actually revalidates
          Exp,       \* the token's exp, as a time
          MaxTime    \* how far the model runs

VARIABLES now,        \* the clock
          streaming,  \* whether the stream is running
          lastCheck,  \* when the relay last validated the token
          revoked,    \* the time the token was revoked, or 0 if it was not
          deadSince   \* when the token stopped being acceptable, or 0 while it is

vars == <<now, streaming, lastCheck, revoked, deadSince>>

Acceptable(t) == t < Exp /\ (revoked = 0 \/ t < revoked)

Init ==
    /\ now = 1
    /\ streaming = TRUE      \* the stream starts on a token just validated
    /\ lastCheck = 1
    /\ revoked = 0
    /\ deadSince = 0

\* Time passes, unless the relay owes a check now: a check is due once Interval has passed.
Tick ==
    /\ now < MaxTime
    /\ ~(streaming /\ now - lastCheck >= Interval)
    /\ now' = now + 1
    /\ deadSince' = IF deadSince = 0 /\ ~Acceptable(now + 1) THEN now + 1 ELSE deadSince
    /\ UNCHANGED <<streaming, lastCheck, revoked>>

\* The relay revalidates, as soon as it is due or earlier, and stops the stream on an unacceptable token.
Check ==
    /\ streaming
    /\ lastCheck' = now
    /\ streaming' = Acceptable(now)
    /\ UNCHANGED <<now, revoked, deadSince>>

\* The issuer revokes the token at any moment.
Revoke ==
    /\ revoked = 0
    /\ revoked' = now
    /\ deadSince' = IF deadSince = 0 THEN now ELSE deadSince
    /\ UNCHANGED <<now, streaming, lastCheck>>

Next == Tick \/ Check \/ Revoke

Spec == Init /\ [][Next]_vars

\* The property the draft asks for: a stream never runs more than Reval seconds on a token that is no longer
\* acceptable.
BoundedLateness == streaming /\ deadSince # 0 => now - deadSince <= Reval
==================================================================================
