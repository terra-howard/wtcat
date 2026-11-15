// Package cat validates Common Access Tokens (CTA-5007-B), built on package cwt.
//
// The package is at phase 1 of decision 0015 (docs/decisions/0015-reconciling-with-cta-5007-b.md). Section numbers
// in comments refer to CTA-5007-B, which is free to download from CTA and is not reproduced here (decision 0014).
//
// Where things are. Each source file's tests are in the test file of the same name; tests that need the package's
// internals are in the matching _internal_test.go file.
//
//	decode.go         the token's text form: strict base64url and the length limit
//	deterministic.go  the deterministic-encoding check of section 4.5
//	claims.go         Claims and the claim-set decoder: core claims, catv, tag rules, claims not yet enforced
//	date.go           NumericDate, exact for integer and floating-point dates
package cat
