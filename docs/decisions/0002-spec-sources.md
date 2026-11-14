# 0002. Where the specification comes from

- **Status:** accepted, 2026-11-14 (option C)
- **Decided by:** Terra Howard

## Context

The authoritative text is CTA-5007-B, "Common Access Token", April 2025. The owner reports it is downloadable
only by CTA members. Without it, some claim semantics cannot be established, and a validator built on guesses
would be wrong in ways no test written here could catch.

Public sources, and what each one settles:

| Source | Settles | Limits |
|---|---|---|
| [RFC 8392][rfc8392], CBOR Web Token | The token format CAT is built on, with worked examples in Appendix A (claims set, keys, signed, MACed, encrypted and nested tokens) | Says nothing about CAT's own claims |
| [IANA CWT Claims registry][iana] | Every CAT claim's name, key and value type (for example `catu` is a map, `catr` is a map, `catreplay` is an unsigned integer) | Names and types only, not behaviour |
| [IETF CDNI client access control draft][cdni] (Disney, Lumen, Qwilt) | How CDNs configure CAT, and that the `catif` claim shapes the response to a valid but rejected token | Defers processing rules to CTA-5007-B |
| [IETF CAT for MOQT draft][c4m] | How CAT is extended for Media over QUIC; cites CTA-5007-B sections | Extension, not the base claims |
| [Akamai EdgeWorkers CAT module][akamai] | One vendor's JSON form of the claims and renewal options (`renewabletype`, `expext`, `deadline`) | One implementation's reading |
| Open-source implementations: [Fastly rust-cat][fastly] (MIT), [Eyevinn node-cat][eyevinn] (MIT), [Quicr catapult][catapult] (BSD-2-Clause) | Tokens they produce can serve as interoperability fixtures | Their readings of the spec, which may share a mistake |

One more fact for the record: the [CTA-WAVE discussion repository][ctawave] notes CTA's patent policy for "shall"
requirements that point to an essential patent, and that CTA does not identify such patents. Worth knowing before
the code goes public.

## Options

- **A. The owner obtains CTA-5007-B,** if a free account allows it. Then every claim can be built against the
  real text.
- **B. Build what public sources establish, now.** The CWT core from RFC 8392, which is complete and comes with
  worked examples, plus claims whose behaviour public sources settle. Everything else is marked `spec-needed`.
- **C. Both:** start B immediately, and widen to the full claim set if A comes through.

## Decision

C. Build the CWT core from RFC 8392 now, plus claims whose behaviour public sources settle, and widen to the full
claim set if CTA-5007-B becomes available. Everything not established by a source above is marked `spec-needed`.

[rfc8392]: https://www.rfc-editor.org/rfc/rfc8392
[iana]: https://www.iana.org/assignments/cwt/
[cdni]: https://datatracker.ietf.org/doc/draft-ietf-cdni-client-access-control-metadata/
[c4m]: https://datatracker.ietf.org/doc/draft-ietf-moq-c4m/
[akamai]: https://techdocs.akamai.com/edgeworkers/docs/cat
[fastly]: https://github.com/fastly/rust-cat
[eyevinn]: https://github.com/Eyevinn/node-cat
[catapult]: https://github.com/Quicr/catapult
[ctawave]: https://github.com/cta-wave/common-access-token

**Update, 2026-11-14:** the owner obtained CTA-5007-B the same day, as a free ($0) purchase from CTA's shop, so the
membership requirement described above was wrong. The full claim set can now be built against
the real text. How it may be used in this public repository is decision 0014; where it changes earlier decisions is
0015.
