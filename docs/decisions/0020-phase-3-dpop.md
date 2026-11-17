# 0020. Phase 3: `cnf`, `catdpop` and DPoP proofs

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation; pending her review. She may reverse it.
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-17).

## Question asked

Decision 0018 chose a narrow JWS verifier of this project's own for phase 3. What would an expert accept, refuse
and leave out?

## Reasoning

- **Verify exactly what RFC 9449 Section 4.3 lists, and nothing a token can widen.** The proof's key comes from its
  own header, which is only safe because its RFC 7638 thumbprint must equal the `jkt` in the already verified CAT.
  Everything else the proof says is checked against the request.
- **Read JSON by exact member names.** Go's `encoding/json` matches struct fields case-insensitively, so a header
  with `"TYP"` would pass as `"typ"`. The verifier decodes into maps of raw values and reads members by their exact
  names.
- **Choose the permitted option that needs no state.** `catdpop`'s `jti` setting only ever allows a recipient to
  track used `jti` values, never requires it (section 4.8.2.3). Tracking needs a shared store across a recipient's
  machines, which a validator library cannot supply well. So `jti` is never a reason to refuse here, and the
  documentation says replay protection then rests on the window.

## Decision

1. **`cnf` (8)** must be a map holding `jkt` (323), a 32-byte byte string, and nothing else this version can check.
   A `cnf` without `jkt`, or with another confirmation method, is unsupported, since section 4.8.1 lets a recipient
   refuse methods it cannot satisfy.
2. **The proof:** exactly one `DPoP` field in the request, a compact JWS of three base64url parts without padding,
   whose header has `typ` `dpop+jwt`, `alg` `ES256` (required by section 4.3.1.1.1) or `PS256`, and a `jwk` that is a
   public EC P-256 or RSA key (of at least 2048 bits) matching `alg`, with no private members. The signature must
   verify; the payload must have a non-empty string `jti`, `htm` equal to the request method, `htu` equal to the
   request URI after the normalization of decision 0017 with query and fragment removed, and a numeric `iat`
   within the window of `now`. The key's RFC 7638 thumbprint must equal `jkt`.
3. **`ath`** must be present and equal the base64url SHA-256 of the token's text when the token arrived in the
   `DPoP` authorization scheme (section 4.4, RFC 9449 Section 7); otherwise it is checked only if present.
4. **`catdpop` (321):** `window` (0), in seconds, sets the window when present; otherwise the `Validator`'s
   `DPoPWindow` applies, default 60 seconds, the same on both sides of `now`. `jti` (1) never causes a refusal.
   `crit` (-1) listing -1, 0 or 1 is malformed, and listing any key this version does not know is unsupported.
   Other settings are ignored. `catdpop` without `cnf` constrains nothing and is accepted.
5. **A token in the `DPoP` authorization scheme without a `cnf` `jkt`** is unacceptable, since RFC 9449 Section 7
   requires such a token to be bound to the proof's key.
6. **Errors:** a proof that fails any check makes the token unacceptable (`cat.ErrProof`), because section 4.8.1
   says the `cnf` claim is rejected, not that the token is invalid.
7. **Outside vectors:** RFC 7638's worked thumbprint, and RFC 9449's example proofs where their signatures verify.
