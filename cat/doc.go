// Package cat validates Common Access Tokens (CTA-5007-B): the CBOR Web Tokens that CDNs use to decide whether a
// request may fetch content. It is built on package cwt.
//
// A Validator holds the recipient's keys, the names it answers to, and a clock. Validate checks a token on its
// own. ValidateRequest checks it with the request it came with, for the claims that restrict methods, URIs,
// headers, networks, places and connections. Package cathttp does this for HTTP servers, finding the tokens in
// each request first.
//
// A token is invalid when it is not well formed, not authentic, or not of a shape this version can check: the
// error wraps cwt.ErrMalformed, cwt.ErrVerification or cwt.ErrUnsupported. It is unacceptable when it is valid
// but one of its claims refuses it: the error is a *Unacceptable, which wraps ErrUnacceptable and a more specific
// error such as ErrExpired (section 4.3.1.2).
//
// Section numbers in comments refer to CTA-5007-B, which is free to download from CTA and is not reproduced here
// (decision 0014).
//
// # Claims this version enforces
//
// Section 4.3.1.5 asks recipients to say which claims they support. This version enforces:
//
//	iss (1)              must equal the issuer configured with the key that verified the token
//	aud (3)              a string or an array; must name one of the Validator's Audiences
//	exp (4)              the current time must be before it, with no leeway
//	nbf (5)              the current time must not be before it, with no leeway
//	cnf (8)              with jkt: the request's DPoP proof must be made with that key and match the request
//	catreplay (308)      with Validator.Replay set: 1 or 2 refuses a cti seen before; 0 never refuses
//	catv (310)           must be 1
//	catnip (311)         the client's address must lie in a listed prefix, or its ASN be listed
//	catu (312)           each URI component must match, after normalization
//	catm (313)           must list the request's method, case-sensitively
//	catalpn (314)        with Request.Connection set: the negotiated ALPN must be listed
//	cath (315)           each named header must be present and match
//	catgeoiso3166 (316)  with Request.Location set: the client must be in a listed country or region
//	cattpk (319)         with Request.Connection set: a client certificate must have the listed key
//	catdpop (321)        sets the DPoP proof's window; crit is honoured; jti never causes a refusal
//
// cnf, catnip, catu, catm and cath need ValidateRequest: Validate refuses tokens carrying them as unsupported,
// since it has nothing to check them against. A cnf with a confirmation method other than jkt is refused as
// unsupported too. sub (2), iat (6) and cti (7) are decoded and type-checked, and are informational here.
//
// Every other claim is ignored, as section 4.5 requires of claims a recipient does not support: catpor,
// catgeocoord, geohash, catgeoalt and catifdata, and catreplay, catgeoiso3166, catalpn and cattpk when the caller
// does not supply what they need (decision 0021).
//
// # Issuing tokens
//
// With an Issuance configured, a Validator issues tokens too (decision 0022). Validator.Renew follows catr (323),
// renewing an acceptable token. Validator.IfResponse follows catif (322), building the response a refused token
// asks for, with any tokens it asks to be minted. Without an Issuance, catr is ignored and minted tokens are empty,
// as the specification allows.
//
// # Details
//
// Algorithms: HMAC 256/64, HMAC 256/256, ES256 and PS256, in COSE_Mac0 or COSE_Sign1, each key bound to one of
// them. Encrypted tokens and messages with more than one signer or recipient are not supported.
//
// For catu, Request.URI must be the absolute request URI with the token already removed, as section 4.6.10
// describes; package cathttp does this. This package normalizes it before matching (RFC 9110 Section 4.2.3, RFC
// 3986 Sections 6.2.2 and 6.2.3), so a default port becomes the empty port component.
//
// A catnip claim naming a full address, or a prefix longer than /24 (IPv4) or /56 (IPv6), is malformed: section
// 4.6.9 requires such values to be encrypted, and this package does not decrypt tokens.
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
//	validator.go      Validator, Key, Token, Validate and the acceptance errors of the core claims
//	request.go        Request, ValidateRequest, catm, catu, cath and catnip (decision 0017)
//	catif.go          catif: Unacceptable and Validator.IfResponse (decision 0022)
//	renew.go          catr: Validator.Renew, Issuance and Renewal (decision 0022)
//	match.go          the match types of section 4.6.10, used by cath and catu, and the POSIX regex checks
//	uri.go            request URI normalization and the nine catu components
//	network.go        catnip: ASNs and RFC 9164 prefixes
//	connection.go     catalpn, cattpk and Connection
//	geo.go            catgeoiso3166 and Location
//	dpop.go           cnf and catdpop: DPoP proofs, keys from jwk, RFC 7638 thumbprints (decision 0020)
//	decode.go         the token's text form: strict base64url and the length limit
//	deterministic.go  the deterministic-encoding check of section 4.5
//	claims.go         Claims, the claim keys, and the claim-set decoder with its tag rules
//
//	helpers_test.go   token builders shared by the external tests
//	example_test.go   ExampleValidator, checked by go test
//	cta_test.go       tests against CTA-5007-B's own examples, built with -tags cta (decision 0014)
//	interop_test.go   fixtures from other CAT implementations, judged by the specification (decision 0026)
package cat
