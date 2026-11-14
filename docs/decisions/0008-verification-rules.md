# 0008. Verification rules for version zero

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation for an experiment (see decision 0007). Pending her
  review; she may reverse it.

## Question asked

Implementing decision 0006 forces a series of small choices the specification either settles or leaves open.
What would an expert do with each?

## Reasoning and rules

The expert default for a verifier is: follow the specification where it speaks, be strict where strictness
removes ambiguity an attacker could use, and refuse explicitly (`ErrUnsupported`) rather than guess where the
code does not yet handle something.

1. **Tags.** RFC 8392 Section 6: a CWT tag (61), if present, "MUST prefix a tagged object using one of the COSE
   CBOR tags". So tag 61 followed by an untagged array is `ErrMalformed`. A COSE tag that does not match the
   function (17 for COSE_Mac0, 18 for COSE_Sign1) is `ErrMalformed`. An untagged COSE array is accepted, since
   RFC 8392 Section 7.2 lets the application context decide the type, and the function called is that context.
2. **Header parameters.** RFC 8392 Section 7.2, step 4: verify the header "includes only parameters and values
   whose syntax and semantics are both understood and supported". Version zero understands `alg` (1) and `kid`
   (4). Any other label, in either header, is `ErrUnsupported`. `alg` must be in the protected header, because an
   unprotected algorithm can be changed without breaking the MAC or signature.
3. **Payload.** A detached payload (CBOR null) is `ErrUnsupported`. A payload that begins with a COSE tag is a
   nested CWT (Section 7.2, step 6) and is `ErrUnsupported` for now. Otherwise it must decode as a claims map.
4. **Claim values.** RFC 8392 Section 3: claim values "MUST NOT be prefixed with any CBOR tag", so a tagged
   registered claim is `ErrMalformed`. `iss`, `sub` and `aud` must be text strings, `cti` a byte string, and
   `exp`, `nbf` and `iat` integers. A floating-point date is `ErrUnsupported` (decision 0006).
5. **Duplicate map keys** are rejected wherever they occur. Two values for one claim or header parameter is
   exactly the ambiguity an attacker uses, where one component reads the first and another reads the last.
   Invalid UTF-8 in text strings is rejected. Indefinite-length items are allowed, because RFC 9052 does not
   forbid them and rejecting them would break interoperability for no security gain.
6. **A key of the wrong type for the token's algorithm** is `ErrVerification`: that key cannot verify that token.
7. **Algorithms.** HMAC 256/64 (4) and HMAC 256/256 (5) for COSE_Mac0; ES256 (-7) for COSE_Sign1, with the key
   required to be on P-256 and the signature to be exactly 64 bytes. **PS256 (-37) is deferred** and returns
   `ErrUnsupported`. Its only test here would be our own code signing and verifying with itself, which proves
   symmetry, not correctness. An expert does not ship cryptographic verification without an outside test vector.
   PS256 returns once one exists (for example a token produced by another CAT implementation, recorded as a
   fixture with its source and licence). This narrows decision 0006, which listed PS256.
