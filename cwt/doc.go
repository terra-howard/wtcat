// Package cwt decodes CBOR Web Tokens (RFC 8392), verifies their COSE protection, and issues them.
//
// There are three ways to verify a token. VerifyMac0 and VerifySign1 take one key and check one kind of message.
// A Verifier adds an allow-list of algorithms, a key lookup by kid and algorithm, and a clock. VerifyMessage, for
// profiles such as the Common Access Token, binds each key to one algorithm and leaves the payload to the caller.
// Issue makes COSE_Mac0 and COSE_Sign1 tokens with the same algorithms.
//
// Every error for a bad token wraps ErrMalformed, ErrVerification or ErrUnsupported, and the time checks add
// ErrExpired, ErrNotYetValid and ErrMissingExpiry; test for them with errors.Is.
//
// The API is set by decisions 0006, 0012, 0015, 0016 and 0022 in docs/decisions, and the verification rules by
// 0008.
//
// # Where things are
//
// Each source file's tests are in the test file of the same name; tests that need the package's internals are in
// the matching _internal_test.go file.
//
//	cwt.go        the Claims type, the error kinds and the helpers that make them
//	algorithm.go  Algorithm, and the one path from an algorithm and a key to a verified MAC or signature
//	claims.go     DecodeClaims and the strict CBOR decoder
//	parse.go      the COSE envelope: tags, structure, headers (tested through mac0_test.go and sign1_test.go)
//	mac0.go       VerifyMac0 and the MAC structure
//	sign1.go      VerifySign1, ES256, PS256 and the signature structure
//	time.go       Claims.CheckTime
//	date.go       NumericDate, exact for integer and floating-point dates (decision 0016); package cat uses it too
//	verifier.go   Verifier
//	message.go    VerifyMessage, Key and Message: keys bound to one algorithm, alg optional (decision 0015)
//	multi.go      COSE_Sign and COSE_Mac with direct recipients, for VerifyMessage (decision 0029)
//	encrypt0.go   DecryptMessage and IsEncrypted: COSE_Encrypt0 with AES-GCM (decision 0030)
//	issue.go      Issue and SigningKey: issuing COSE_Mac0 and COSE_Sign1 tokens (decision 0022)
//
//	helpers_test.go           helpers and the RFC 8392 Appendix A values shared by the external tests
//	vectors_internal_test.go  helpers for the COSE working group vectors in testdata/cose-wg
//	example_test.go           ExampleVerifier and ExampleIssue, checked by go test
//
// The protected tests that define what the package promises are in ../conformance, guarded by the census.
package cwt
