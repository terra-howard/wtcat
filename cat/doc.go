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
//	catnip (311) the client's address must lie in a listed prefix, or its ASN be listed (needs ValidateRequest)
//	cnf (8)     with jkt: the request's DPoP proof must be made with that key and match the request (needs ValidateRequest)
//	catdpop (321) sets the proof's window; crit is honoured; jti never causes a refusal (decision 0020)
//	catreplay (308) with Validator.Replay set: 1 or 2 refuses a cti seen before; 0 never refuses (decision 0021)
//	catgeoiso3166 (316) with Request.Location set: the client must be in a listed country or region
//	catalpn (314), cattpk (319) with Request.Connection set: the TLS ALPN, or a client certificate's key, must match
//
// It decodes and type-checks sub (2), iat (6) and cti (7), which are informational here. Every claim CTA-5007-B
// requires recipients to support is enforced; a cnf with a confirmation method other than jkt is refused as
// unsupported. Every other claim is
// ignored, as section 4.5 requires of claims a recipient does not support, including the optional catpor,
// catgeocoord, geohash, catgeoalt and catifdata, and catreplay, catgeoiso3166, catalpn, cattpk and catr when the
// caller does not supply what they need. catr is followed through Validator.Renew when Issuance is set, and catif
// through Validator.IfResponse for a refusal that is a *Unacceptable.
//
// Algorithms: HMAC 256/64, HMAC 256/256, ES256 and PS256, in COSE_Mac0 or COSE_Sign1, each key bound to one of
// them. Encrypted tokens and messages with more than one signer or recipient are not supported.
//
// For catu, Request.URI must be the absolute request URI with the token already removed, as section 4.6.10
// describes (package cathttp does this); this package normalizes it (RFC 9110 Section 4.2.3, RFC 3986 Sections 6.2.2 and 6.2.3) before
// matching, so a default port becomes the empty port component. A catnip claim naming a full address, or a
// prefix longer than /24 (IPv4) or /56 (IPv6), is malformed: section 4.6.9 requires such values to be encrypted,
// and this package does not decrypt tokens.
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
//	catif.go          catif: Unacceptable and Validator.IfResponse (decision 0022)
//	renew.go          catr: Validator.Renew, Issuance and Renewal (decision 0022)
//	request.go        Request, ValidateRequest and the request claims (decision 0017)
//	match.go          the match types of section 4.6.10, used by cath and catu, and the POSIX regex checks
//	uri.go            request URI normalization and the nine catu components
//	network.go        catnip: ASNs and RFC 9164 prefixes
//	connection.go     catalpn, cattpk and Connection
//	geo.go            catgeoiso3166 and Location
//	dpop.go           DPoP proofs: compact JWS with ES256 or PS256, keys from jwk, RFC 7638 thumbprints (decision 0020)
//	decode.go         the token's text form: strict base64url and the length limit
//	deterministic.go  the deterministic-encoding check of section 4.5
//	claims.go         Claims and the claim-set decoder: core claims, catv, tag rules, claims not yet enforced
//
//	helpers_test.go   token builders shared by the external tests
//	example_test.go   ExampleValidator, checked by go test
package cat
