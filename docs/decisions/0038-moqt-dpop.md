# 0038. DPoP proofs as CWTs for MOQT

- **Status:** accepted, 2026-11-18
- **Decided by:** Claude, under Terra Howard's delegation (the MoQT roadmap, item 5).
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-18).

## Question asked

Decision 0020 checks DPoP proofs for HTTP: a JWT in the `DPoP` header field, bound to the request by `htm` and
`htu`. draft-ietf-moq-c4m replaces that half of RFC 9449 for MOQT with a CWT proof whose `actx` claim names the
MOQT action. How should `cat` check it?

## What the draft establishes

Paraphrased, draft-ietf-moq-c4m section "DPoP for MOQT":

- **The token** binds a key with `cnf`. It should use `ckt` (key 5), the COSE Key Thumbprint of RFC 9679, which
  relays must support. It may use CAT's `jkt`, which relays should support. A token with `cnf` must not be
  accepted for an MOQT action without a valid proof.
- **The proof** is a new COSE_Sign1 for each action. Its protected header carries an asymmetric `alg` (ES256
  required, ES384 and EdDSA recommended), `typ` `"dpop-proof+cwt"`, and `kccs` (label 14, RFC 9528), a CWT Claims
  Set whose `cnf` carries the client's COSE_Key. Its payload carries `cti`, an integer `iat`, `actx` (the type
  `"moqt"`, the action, and the Track Namespace and Track Name when the action targets them, exact bytes), and
  `ath`, the SHA-256 of the token as presented.
- **The relay** checks the signature with the key in `kccs`, the key against `cnf`, `ath`, `iat` within
  `catdpop`'s window, the `cti` against proofs accepted within that window when `catdpop` asks for replay
  detection, and that `actx` names the very action, namespace and track. Then it authorizes the action as usual.
- `actx` and `ath` have no claim keys yet (TBD), and the Appendix A vectors have no proofs and no private-use keys
  for them.

## What was checked

- Task 74, the third TLA+ model (`specs/proofreplay/`): a store that forgets a proof's `cti` a window after first
  seeing it accepts the proof twice when its `iat` is in the future, since the proof stays fresh until `iat` plus
  the window. Keeping the `cti` until `iat` plus the window holds.
- Task 74 also confirmed that the draft's example `ckt` is the RFC 9679 thumbprint of its Appendix A ES256 key.

## Reasoning

- **The proof travels with the action.** `MOQTAction.Proof` holds the COSE_Sign1 bytes, tagged or not. How MOQT
  messages carry them is the integration package's business (roadmap item 7).
- **No default claim keys for `actx` and `ath`.** For `moqt` and `moqt-reval` the vectors use private-use keys,
  and decision 0035 follows them. Nothing gives keys for `actx` and `ath`, and inventing values would look like
  interoperability that does not exist. `Validator.ActxKey` and `Validator.AthKey` must be set, by agreement with
  the issuer's clients. While either is zero, a token with `cnf` is refused for MOQT actions as unsupported.
- **`ath` hashes the token's bytes.** Over MOQT a token is presented as bytes, the CBOR itself, so `ath` is the
  SHA-256 of the bytes `ValidateRequest` decodes from its text. The decoding is strict base64url, so those bytes
  are exactly the ones the client sent.
- **Both confirmation methods, and each one present must match.** `cnf` may carry `ckt`, `jkt` or both. For `jkt`
  over MOQT, the thumbprint is that of the JWK equivalent to the COSE_Key (`crv`, `kty`, `x` and `y` for an EC2
  key), as the draft says. Over HTTP, proofs are JWTs checked by `jkt` (decision 0020), so a token whose `cnf`
  names `ckt` is refused there (`cat.ErrProof`), since that method cannot be checked against a JWT proof here. A
  `cnf` that names no method this package checks stays unsupported.
- **ES256 only, for now.** The draft requires ES256 and recommends ES384 and EdDSA. A proof with another `alg` is
  refused as unsupported (`cat.ErrProof`); the two recommended algorithms are a recorded next step, not a silent
  gap. Symmetric algorithms are refused, as the draft requires.
- **The key in `kccs` must be public.** A COSE_Key carrying `d` is refused, as a JWK with private members is over
  HTTP, and the key's curve must be P-256 with points on the curve.
- **Strict `actx`.** `type` must be `"moqt"`, and a key other than 0 to 3 makes the proof fail, since an
  unrecognized part of the authorization context cannot be checked. The action must equal the request's. The
  namespace fields must equal the request's in number and bytes, with an absent key 2 meaning no fields, since a
  real MOQT namespace has at least one. The Track Name must be present exactly when the request has one, and equal
  to it, keeping decision 0035's difference between no track name and an empty one.
- **`iat` is an integer,** as the draft's CDDL says, and must be within the window either way, as over HTTP: the
  `catdpop` window, else `Validator.DPoPWindow`, else 60 seconds.
- **Replay detection when asked, with a store the caller supplies.** When `catdpop`'s `jti` setting is not 0,
  `Validator.ProofReplay(cti, until)` records the proof's `cti` and reports whether it was seen, with `until` the
  proof's `iat` plus the window (task 74). It must be atomic and shared, like `Replay` (decision 0032). Without
  it, nothing is refused for reuse, and replay protection rests on the window, as decisions 0020, 0021 and 0037 do
  for the other stores. It is called after every other check but `catreplay`'s, which stays last. A proof is made
  for one action, so using one up on a request that `catreplay` then refuses costs nothing, while the other order
  would use up the token's `cti` on a request refused for its proof.

## Decision

1. `cnf` may carry `ckt` (5) as well as `jkt`. Both are 32 bytes. A request must satisfy each method the token
   names. Over HTTP a token naming `ckt` is refused, since an HTTP proof is checked by `jkt` alone.
2. For a MOQT request and a token with `cnf`: `MOQTAction.Proof` must hold an ES256 COSE_Sign1 proof that passes
   the draft's relay checks, with `actx` at `Validator.ActxKey` and `ath` at `Validator.AthKey`; otherwise
   `cat.ErrProof`, or `cwt.ErrUnsupported` while either key is unset.
3. `Validator.ProofReplay`, if set, is called after every other check but `catreplay`'s, with `until` the proof's
   `iat` plus the window, when `catdpop` asks for replay detection.
4. Tests build proofs with the Appendix A ES256 key and check the draft's example `ckt`.
