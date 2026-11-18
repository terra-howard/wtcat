# 0039. catmoqt: a MOQT integration package with no transport dependency

- **Status:** accepted, 2026-11-18
- **Decided by:** Terra Howard, that the package depends on no MOQT library (*"Library-free core."*, after the
  survey below). Its shape was chosen by Claude under her delegation (the MoQT roadmap, item 7).
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-18).

## Question asked

`cathttp` lets an HTTP server use `cat` in a few lines. What is its counterpart for a MOQT relay, when no Go MOQT
library yet carries draft-ietf-moq-c4m's tokens?

## What was found

- **The libraries** (2026-11-18). `mengelbart/moqtransport` implements IETF MOQT at about draft 18, and its helper
  for authorization tokens is marked unused. `qumo-dev/gomoqt` implements MOQ Lite, not IETF MOQT, and needs Go
  1.27. draft-ietf-moq-c4m targets draft-ietf-moq-transport-22.
- **What draft 22 asks of a receiver** (section "Authorization Token Compression", paraphrased). A token arrives as
  the value of an AUTHORIZATION TOKEN message parameter (type 0x03), or of the Setup Option of the same number. That
  value is a Token structure: an Alias Type (DELETE 0, REGISTER 1, USE_ALIAS 2, USE_VALUE 3), then an alias, a
  Token Type and a Token Value as the type requires, the integers in draft 22's own variable-length encoding (1 to
  9 bytes, the length in the leading one bits, not QUIC's). Token Type 0x01 is a CAT (draft-ietf-moq-c4m). A
  REGISTER puts the alias in a per-session cache, of at most the MAX_AUTH_TOKEN_CACHE_SIZE this endpoint advertised
  (default 0, no aliases), each entry counting 16 bytes plus its value, and it registers even when the message is
  then refused. A structure that cannot be decoded closes the session (KEY_VALUE_FORMATTING_ERROR), as do a REGISTER
  of an alias in use (DUPLICATE_AUTH_TOKEN_ALIAS) and one past the limit (AUTH_TOKEN_CACHE_OVERFLOW). In SETUP,
  DELETE and USE_ALIAS close the session (PROTOCOL_VIOLATION), and a REGISTER past the limit is used as USE_VALUE.
  Every request travels on its own stream, so messages touching the cache arrive in any order.
- **Task 77, the fourth TLA+ model** (`specs/tokencache/`): the draft's two rules for senders do not keep a sender
  that follows them from meeting UNKNOWN_AUTH_TOKEN_ALIAS (a DELETE on one stream processed before its REGISTER on
  another) or DUPLICATE_AUTH_TOKEN_ALIAS (a REGISTER of a deleted alias processed before the DELETE). Two more
  rules close both. A receiver can do nothing about either, since both are the errors the draft tells it to raise,
  so this goes to the working group (a draft report is with the owner), and the package follows the draft.

## Reasoning

- **The boundary is the Token structure.** Any MOQT stack parses its messages' parameters. Below that, the token
  cache, the CAT and the error codes are authorization's business, and they are the same whichever stack is used.
  So `catmoqt` takes each AUTHORIZATION TOKEN value as bytes, with the action, the Track Namespace and the Track
  Name, and answers with a grant or a refusal carrying the draft's code. A thin adapter for a library can come when
  one carries draft 22's tokens.
- **One `Session` per MOQT session,** on the receiving side: the `cat.Validator`, the connection's ID (for
  `catreplay`, decision 0037), the advertised cache limit, and the cache. Its methods are safe for concurrent use,
  and each message's token operations happen as one step under a lock, which is what the model assumes of a
  receiver.
- **Every token operation first, then judging.** The draft registers an alias even for a message it then refuses,
  so all of a message's Token structures are applied to the cache before any CAT is validated. A CAT is judged as a
  base64url text of its bytes, which `cat` decodes strictly back to the same bytes, so `ath` (decision 0038) and
  everything else see what the client sent.
- **Which tokens count.** Only Token Type 0x01 is a CAT. Tokens of other types still occupy the cache but are not
  judged; a caller that understands them can read them from the session. A message may repeat a token only if the
  resolved type and value differ (draft 22); a repeat is refused as MALFORMED_AUTH_TOKEN. The action is granted by
  the first CAT that is acceptable for it. If none is, the refusal is named after the first CAT's failure: an
  expired token gives EXPIRED_AUTH_TOKEN, a malformed one MALFORMED_AUTH_TOKEN, anything else UNAUTHORIZED. A
  message with no CAT is UNAUTHORIZED.
- **Request or session.** A refused request is a REQUEST_ERROR code (UNAUTHORIZED 0x1, MALFORMED_AUTH_TOKEN 0x4,
  EXPIRED_AUTH_TOKEN 0x5). A refused SETUP closes the session, with the session codes of the same names (0x2, 0x16,
  0x18). Cache errors always close the session. An unknown alias is the draft's UNKNOWN_AUTH_TOKEN_ALIAS (0x17),
  the only code it defines for one, which is a session code although the text says "reject the message"; the
  report to the working group asks which is meant, and until then the package closes the session.
- **Revalidation stays with the relay,** as decision 0036 has it. A grant reports the token's `moqt-reval` interval
  and can check the same token against the same action again; the relay runs the timer, and on a failure ends the
  subscription (PUBLISH_DONE UNAUTHORIZED, or a stream reset with EXPIRED_AUTH_TOKEN).
- **The DPoP proof is the caller's input.** draft-ietf-moq-c4m does not yet say how a proof travels with an action
  (raised in the c4m report), so the caller passes it with the request.
- **The client's side is out of scope.** The package judges tokens a relay receives. Registering aliases as a
  sender is a client's concern.

## Decision

1. A new package, `catmoqt`, with `Session`, `Request`, `Grant` and `Error`, depending on `cat` and `cwt` only.
2. It decodes draft 22's Token structures, keeps the per-session cache with its limit and rules, judges Token Type
   0x01 with `cat`, and reports refusals with draft 22's request and session codes, as above.
3. Its tests use the draft's integer encoding examples and the draft-ietf-moq-c4m vectors, and it gets its own
   mutation-testing configuration and CI job.
