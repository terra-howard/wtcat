# 0017. Phase 2: the request claims

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation; pending her review. She may reverse it.

## Question asked

Phase 2 of decision 0015 enforces `catm`, `cath`, `catu` and `catnip`, which compare a token with the request it
arrived on. What would an expert do with the request's shape, and with the places CTA-5007-B leaves room?

## Reasoning

- **Keep the validator free of HTTP plumbing, but give it everything a claim compares.** The claims need the
  method, the URI, the header fields, the client's address and its autonomous system number. A plain struct
  carries them, so the validator works the same behind any HTTP server, proxy or edge runtime. Where the token
  was found, and removing it, belongs with the code that found it: the separate integration package decision
  0015 set aside.
- **Fail closed when a claim cannot be checked.** `Validate` without a request cannot check request claims, so it
  refuses tokens that carry one, as phase 1 did. A new `ValidateRequest` checks them.
- **Use a regular-expression engine that cannot be made to run long.** Section 4.6.10 requires POSIX extended
  regular expressions and resource limits. Go's `regexp.CompilePOSIX` takes POSIX ERE syntax with leftmost-longest
  matching, and runs in time linear in the input, so no expression in a token can stall the recipient. Its one
  divergence is documented by the Go project: among several leftmost-longest matches, it assigns groups as a
  backtracking search would, not by POSIX's rule of maximizing each group in turn. That matters only for the
  optional group comparisons, and only for ambiguous expressions. A backtracking POSIX engine would match the
  rule exactly and give up the time bound, which is the worse trade for a recipient facing untrusted tokens.
- **Settle the specification's ambiguities toward refusal, and write each one down.**

## Decision

1. **The request.**

   ```go
   type Request struct {
   	Method    string      // compared case-sensitively (catm)
   	URI       string      // the absolute request URI, with the token already removed (catu)
   	Header    http.Header // request header fields (cath)
   	ClientIP  netip.Addr  // the client's address (catnip)
   	ClientASN uint32      // the client's autonomous system number, 0 if unknown (catnip)
   }

   func (v *Validator) ValidateRequest(token string, req *Request) (*Token, error)
   ```

   `Validate(token)` keeps its meaning and refuses tokens with request claims as unsupported. A request claim
   that is not satisfied is unacceptable (`ErrUnacceptable`, with one error per claim); a claim of the wrong shape
   is malformed.
2. **Order of work:** `catm`; then the match engine and `cath`; then URI normalization and `catu`; then `catnip`.
   Each is a task with its own sealed prediction.
3. **`catm`:** an array of at least one text string, untagged. The request's method must equal one of them,
   case-sensitively. No member limit beyond the token's length, which already bounds it.
4. **Matches** (section 4.6.10, used by `catu` and `cath`): exact, prefix, suffix, contains, regular expression,
   SHA-256 and SHA-512/256 are all supported; the two hashes cost one standard-library call each. Every match type
   present in a match map must hold. Any other match type, including the private range at -25 and below, makes the
   token unsupported, since section 4.6.10 requires rejecting claims with match types the recipient does not
   support.
5. **Regular expressions:** `regexp.CompilePOSIX`, unanchored, case-sensitive. An expression it cannot compile,
   including POSIX equivalence classes and collating symbols, which it lacks, makes the token unsupported. Group
   values are compared with the groups of the leftmost-longest match. A null matches anything; a group that did
   not take part in the match equals no string, not even the empty one; more values than groups never match.
6. **`cath`:** header names compare case-insensitively, and a claim with two names that are equal ignoring case
   is malformed (section 4.6.13 allows refusing it). Several field lines of one name are joined with ", " (RFC 9110
   Section 5.2) before matching. A missing header never matches, whatever the match; a header present with an
   empty value is matched as the empty string. This is how this project reads the sentence in 4.6.13 about missing
   and empty headers.
7. **`catu`:** the caller removes the token from the URI first, as section 4.6.10 describes. The validator then
   normalizes as RFC 9110 Section 4.2.3 and RFC 3986 Sections 6.2.2 and 6.2.3 require: lowercase scheme and host,
   uppercase hexadecimal in percent-encodings, decoded unreserved characters, dot segments removed, the default
   port dropped (so the port component is then empty, as the specification's own example shows), and an empty
   path made "/". Components 0 to 8 are taken from the result as section 4.6.10 defines them.
8. **`catnip`:** an array of at least one member, each an unsigned integer (an ASN), or an RFC 9164 address or
   prefix under tag 52 (IPv4) or 54 (IPv6). The address-with-prefix form is malformed. Prefixes must follow RFC
   9164's own encoding rules (no trailing zero bytes, no bits set beyond the prefix length). Because this package
   does not decrypt tokens, any full address, IPv4 prefix longer than 24 bits or IPv6 prefix longer than 56 bits
   is malformed, as section 4.6.9 requires of an unencrypted claim. The request matches if its address lies in a
   listed prefix (an IPv4-mapped IPv6 address counts as IPv4) or its ASN is listed and not 0.

## Consequences

- Token location and removal remain undone until the integration package; until then, callers do it.
- The regular-expression divergence is the one known difference from POSIX, recorded here and in the package
  documentation.

## Update, 2026-11-14, found while building the match engine (task 23)

`regexp.CompilePOSIX` does not reject everything it cannot do. It accepts POSIX equivalence classes (`[[=a=]]`)
and collating symbols (`[[.a.]]`) but reads them as plain characters, and it treats a backslash inside a bracket
expression as an escape where POSIX treats it as a literal. An expression using any of these would be matched
with a meaning its issuer did not write. So before compiling, the package scans bracket expressions and refuses
those three constructs as unsupported, consistent with item 5. One smaller difference is recorded and left: in
Go's POSIX mode `^` and `$` also match at line breaks, which cannot change a result here, because a normalized
URI component and an HTTP field value contain no line breaks.

