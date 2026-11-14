# 0016. Giving `cwt.Claims` the shape RFC 8392 allows

- **Status:** proposed, 2026-11-14
- **Decision needed from:** Terra Howard, because every option but D changes protected tests

## Context

RFC 8392 allows two things `cwt.Claims` cannot hold (decision 0015, "What changed while deciding"):

- an `aud` claim that is an array of strings (Section 3.1.3). `cwt` rejects one as `ErrMalformed`, which is a
  defect: a valid token is called malformed;
- a floating-point NumericDate (Section 2). `cwt` refuses one as `ErrUnsupported`, which is honest but incomplete.

Decision 0006 chose `Audience string` and `*int64` dates, and the protected tests in
`conformance/rfc8392_test.go` compare `c.Audience` with a string and pass `c.Expiry`, `c.NotBefore` and
`c.IssuedAt` to a helper that takes `*int64`. So changing either type stops the protected tests compiling.

Package `cat` does not wait on this decision; it has its own claims type (decision 0015).

## Options

- **A. Change the types, and amend the protected tests in the same commit.** `Audience []string` (a single
  string becomes one element) and a `NumericDate` type holding an integer or a float exactly. The cleanest API.
  The protected tests change only in how they read the values; the values they check, from RFC 8392 Appendix A,
  stay the same.
- **B. Add fields beside the old ones.** Keep `Audience` and the `*int64` dates for the forms they can hold, and
  add `Audiences []string` and `NumericDate` fields that hold every form. No protected test changes, but each
  claim has two fields, and callers must know which to read.
- **C. Accept arrays in `aud` by keeping the first element in `Audience`.** No protected test changes. Rejected
  outright here: it silently drops audiences, so a caller checking `Audience` could refuse a token meant for it
  or, worse, never see an audience it should have checked.
- **D. Leave `cwt` as it is** and document both gaps: `aud` arrays rejected, floating-point dates unsupported.
  Nothing changes; `cwt` stays stricter than RFC 8392.

## Recommendation

A. The package is at version zero and unpublished, so no caller depends on the old types, and a protected test
that pins a mistaken type is exactly the case decision 0003 foresaw when it made changes deliberate rather than
impossible. B costs every future reader of `Claims` a question it should not have to ask. If A is too large a
change to the protected set for now, D is the honest holding position, with the `aud` defect listed in the
README.

## If accepted

The owner edits `conformance/rfc8392_test.go` and `conformance/MANIFEST` (new hash from
`go run ./cmd/census hash conformance/rfc8392_test.go`) in one commit citing this decision. Agents then change
`cwt` to match, with the census gate as the check that nothing the RFC promises was lost.
