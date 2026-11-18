# 0030. Encrypted tokens

- **Status:** accepted, 2026-11-17
- **Decided by:** Claude, under Terra Howard's delegation (2026-11-17, after publication).
- **Review:** unreviewed. The owner has not yet reviewed this decision (marked 2026-11-17).

## Question asked

CTA-5007-B section 4.3.1.1 lets a CAT be an encrypted CWT (RFC 8392 section 7), defines no mandatory algorithm for
one, and lets recipients choose not to support them. Several claims depend on encryption: `catgeocoord` must always
be encrypted, a `geohash` longer than four characters must be, and so must a `catnip` naming an address or a narrow
prefix. A claim in an encrypted token counts as encrypted. The "claims with an encrypted value" that the
specification mentions are not defined anywhere yet. Decision 0005 deferred encryption. Should `cat` decrypt tokens
now, and how?

## Reasoning

- **COSE_Encrypt0 with AES-GCM, direct keys.** A recipient and issuer that share an encryption key is the case that
  matters for CDNs, as with HMAC. AES-GCM (algorithms 1, 2 and 3: 128, 192 and 256-bit keys) is in Go's standard
  library, so no dependency is needed (AGENTS.md rule 6). The COSE working group's `encrypted-tests` and
  `aes-gcm-examples`, at the commit decision 0009 pins, give outside vectors.
- **AES-CCM is left out.** RFC 8392's own encrypted examples (A.5, A.6) use AES-CCM-16-64-128, which neither the
  standard library nor `golang.org/x/crypto` provides. Writing a block-cipher mode here is a risk worth taking only
  for an issuer that needs it, and none is known. It is refused as unsupported, and recorded in the design
  explanation.
- **COSE_Encrypt with several recipients is left out** for the same reason as key wrapping in decision 0029: it
  needs key material this package does not handle.
- **Keys bound to one algorithm, as for verification** (decision 0015). `Validator.DecryptionKeys` returns a
  `cat.Key` for a kid, with the AES-GCM algorithm and its issuer. A nil `DecryptionKeys` means the recipient does
  not decrypt, and an encrypted token is refused as unsupported.
- **The IV.** The IV header (5) must be present and 12 bytes long, protected or not. A Partial IV (6) needs a context
  IV that only a key agreement could supply, and is refused as unsupported. Other headers follow decision 0008.
- **What the plaintext is.** RFC 8392 section 7.1 lets the plaintext be the claim set, or a nested signed or MACed
  CWT. A plaintext that begins with a COSE or CWT tag is a nested message. It is verified with `Validator.Keys`,
  as any token is, and its issuer binding applies. Any other plaintext is a claim set, authenticated by the
  encryption key alone, and the decryption key's issuer binding applies. The plaintext must be deterministically
  encoded, like any claim set.
- **Encrypted claims.** Claims from an encrypted token count as encrypted for sections 4.6.9, 4.6.15 and 4.6.16.
  - `catnip` may then name addresses and narrow prefixes.
  - `geohash` may then be longer than four characters, up to twelve, a cell a few centimetres across.
  - `catgeocoord` is enforced.
- **`catgeocoord`.** The claim is an array of `[latitude, longitude, radius in metres]` locations. A client is
  inside one when its distance from the centre is at most the radius. Distance is the great-circle distance on a
  sphere of the mean Earth radius (6,371,008.8 m), whose error against the WGS84 ellipsoid is under about 0.5%.
  That is small next to a geolocation database's own error, and is documented. Coordinates come from
  `Location.Coordinates`, as for `geohash` (decision 0027): nil means the claim is ignored, and a client outside
  every location is refused. An unencrypted `catgeocoord` makes the claim set invalid, as section 4.6.15 requires.
  CRS Wrappers are refused, as for `geohash`.

## Decision

1. `cwt` gains `DecryptMessage` for tagged or untagged COSE_Encrypt0 with A128GCM, A192GCM or A256GCM and a key
   from a `KeyLookup`, returning the plaintext.
2. `cat.Validator` gains `DecryptionKeys`. Encrypted tokens are decrypted with it, then handled as nested messages
   or claim sets as above, and their claims count as encrypted.
3. `cat` enforces `catgeocoord`, and lifts the encryption limits on `catnip` and `geohash` for encrypted claims.
4. Tests use the COSE working group's encryption vectors at the pinned commit, plus end-to-end `cat` tests.
