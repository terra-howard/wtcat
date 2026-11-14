// Package cwt decodes CBOR Web Tokens (RFC 8392) and verifies their COSE protection.
//
// The API is set by docs/decisions/0006-cwt-package-api.md, 0012 and 0015, and the verification rules by 0008.
//
// Where things are. Each source file's tests are in the test file of the same name; tests that need the package's
// internals are in the matching _internal_test.go file.
//
//	cwt.go       the Claims type and the error kinds
//	claims.go    DecodeClaims and the strict CBOR decoder
//	parse.go     the COSE envelope: tags, structure, headers (tested through mac0_test.go and sign1_test.go)
//	mac0.go      VerifyMac0 and the MAC structure
//	sign1.go     VerifySign1, ES256, PS256 and the signature structure
//	time.go      Claims.CheckTime
//	verifier.go  Verifier
//	message.go   VerifyMessage, Key and Message: keys bound to one algorithm, alg optional (decision 0015)
//
//	helpers_test.go           helpers and the RFC 8392 Appendix A values shared by the external tests
//	vectors_internal_test.go  helpers for the COSE working group vectors in testdata/cose-wg
//	example_test.go           ExampleVerifier, checked by go test
//
// The protected tests that define what the package promises are in ../conformance, guarded by the census.
package cwt
