// Package cat validates Common Access Tokens (CTA-5007-B), built on package cwt.
//
// The package is at phase 1 of decision 0015 (docs/decisions/0015-reconciling-with-cta-5007-b.md). Section numbers
// in comments refer to CTA-5007-B, which is free to download from CTA and is not reproduced here (decision 0014).
//
// # Claims this version supports
//
// Section 4.3.1.5 asks recipients to say which claims they support. This version enforces:
//
//	iss (1)     must equal the issuer configured with the key that verified the token
//	aud (3)     a string or an array; must name one of the Validator's Audiences
//	exp (4)     the current time must be before it, with no leeway
//	nbf (5)     the current time must not be before it, with no leeway
//	catv (310)  must be 1
//	catm (313)  must list the request's method, case-sensitively (needs ValidateRequest)
//	cath (315)  each named header must be present and match (needs ValidateRequest)
//	catu (312)  each URI component must match, after normalization (needs ValidateRequest)
//
// It decodes and type-checks sub (2), iat (6) and cti (7), which are informational here. It refuses, as
// unsupported, any token carrying a claim CTA-5007-B requires recipients to enforce that this version does not
// enforce yet: cnf (8), catnip (311) and catdpop (321). Every other claim is
// ignored, as section 4.5 requires of claims a recipient does not support, including the optional catreplay,
// catpor, catalpn, the geographic claims, cattpk, catifdata, catif and catr.
//
// Algorithms: HMAC 256/64, HMAC 256/256, ES256 and PS256, in COSE_Mac0 or COSE_Sign1, each key bound to one of
// them. Encrypted tokens and messages with more than one signer or recipient are not supported.
//
// For catu, Request.URI must be the absolute request URI with the token already removed, as section 4.6.10
// describes; this package normalizes it (RFC 9110 Section 4.2.3, RFC 3986 Sections 6.2.2 and 6.2.3) before
// matching, so a default port becomes the empty port component.
//
// Regular expressions in matches are POSIX extended regular expressions, run by regexp.CompilePOSIX, which takes
// time linear in its input. Two differences from POSIX are handled as decision 0017 records: among several
// leftmost-longest matches, groups are assigned as a backtracking search would; and equivalence classes,
// collating symbols and backslashes inside brackets, which Go would misread, are refused.
//
// # Where things are
//
// Each source file's tests are in the test file of the same name; tests that need the package's internals are in
// the matching _internal_test.go file.
//
//	validator.go      Validator, Key, Token and the acceptance errors
//	request.go        Request, ValidateRequest and the request claims (decision 0017)
//	match.go          the match types of section 4.6.10, used by cath and catu, and the POSIX regex checks
//	uri.go            request URI normalization and the nine catu components
//	decode.go         the token's text form: strict base64url and the length limit
//	deterministic.go  the deterministic-encoding check of section 4.5
//	claims.go         Claims and the claim-set decoder: core claims, catv, tag rules, claims not yet enforced
//	date.go           NumericDate, exact for integer and floating-point dates
//
//	helpers_test.go   token builders shared by the external tests
//	example_test.go   ExampleValidator, checked by go test
package cat
