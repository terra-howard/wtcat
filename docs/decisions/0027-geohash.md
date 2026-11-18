# 0027. The geohash claim

- **Status:** accepted, 2026-11-17
- **Decided by:** Claude, under Terra Howard's delegation (2026-11-17, after publication).
- **Review:** reviewed and approved by the owner, 2026-11-18 (*"Consider all of the decisions reviewed by me and approved, 0006-0040."*).

## Question asked

The design explanation left `geohash` (282) out because its rules come from CTA-5009-A, which the project had not
read. The owner obtained CTA-5009-A on 2026-11-17. Should `cat` enforce the claim now, and how?

## What the sources establish

Paraphrased, section numbers as given; neither document is reproduced here (decision 0014 applies to CTA-5009-A
too: it carries no permissive licence at all).

- **CTA-5009-A** documents the long-established geohash algorithm: a base-32 alphabet without `a`, `i`, `l` and
  `o`, with longitude and latitude bits interleaved, longitude first. A geohash names a rectangular region; a
  longer one names a smaller region inside every prefix of it. Decoders should read upper case as lower case and
  must not process any other character outside the alphabet (8.1). A point lies in a region when the point,
  encoded at the region's length, gives the same geohash (8.4). The CWT claim is a text string or an array of them,
  an array meaning the union of its regions (13, 14). It must not carry the geohash tag (301), and it may carry a
  CRS Wrapper tag (279) around the whole value or around each string (14).
- **CTA-5007-B 4.6.16** requires rejecting a request that does not come from a listed region. An unwrapped claim is
  WGS84. Recipients must support WGS84, must reject coordinate systems they do not support, and may reject a wrapper
  that only restates the default. **A geohash longer than four characters must be conveyed in an encrypted claim,
  and a recipient must reject one that is not.** Support for the claim is optional.

## Reasoning

- **Build it.** The rules are now established by a source, the algorithm is short, and outside values exist to
  check it against.
- **At most four characters, in practice.** This package does not decrypt (decision 0005), so every token it sees
  is unencrypted, and section 4.6.16 then requires refusing any geohash longer than four characters. Four
  characters is a cell of roughly 39 by 20 km at the equator, which is what an unencrypted claim can carry.
- **Refuse every CRS Wrapper.** Only WGS84 is supported. A wrapper naming another system must be refused, and a
  wrapper naming WGS84 is unnecessary, which the section allows refusing. Telling the two apart would mean
  interpreting EPSG numbers and WKT for no gain.
- **The caller supplies coordinates, not a geohash.** Geolocation databases give latitude and longitude. The
  package encodes the point at each listed geohash's length and compares, as 8.4 describes. `Location` gains
  `Coordinates`, a latitude and longitude, nil when they are not known.
- **Who can't locate, and who failed to.** This follows decision 0021's rule for `catgeoiso3166`. A nil
  `Location`, or one whose coordinates are not known, means the recipient does not locate clients by coordinates,
  and the claim is ignored. A `Location` with known coordinates that are out of range or not finite is a failed
  lookup, and the token is refused.
- **Case.** The claim's strings are compared ignoring case, as 8.1 and 8.4 ask of decoders, although 13 calls the
  strings case-sensitive. Any character outside the alphabet makes the claim malformed.
- **The client's accuracy is the caller's problem.** A database's point estimate can sit in the wrong cell near a
  border. The package documents this and does not guess at accuracy radii.
- **Independent checks.** The encoder is tested against published geohash values from outside CTA, with their
  source recorded, and by property tests: every prefix of an encoded point contains it, and decoding a geohash gives
  a cell that its encoding stays in.

## Decision

1. `cat` enforces `geohash` (282) when `Request.Location` has known coordinates, and ignores it otherwise.
2. The claim must be an untagged text string, or an untagged array of untagged text strings. The CDDL allows an
   empty array, which names no region, so it refuses every located client. Each
   string must be 1 to 4 characters from the geohash alphabet, in either case. Anything else, including any tag, is
   malformed.
3. A client whose coordinates fall in any listed region is accepted. Any other client is refused with
   `cat.ErrLocation`, as are coordinates that are out of range or not finite.
4. The design explanation moves `geohash` from "Deliberately not supported" to the enforced list, and keeps
   longer, encrypted geohashes there.
