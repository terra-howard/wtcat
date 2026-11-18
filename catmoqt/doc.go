// Package catmoqt lets a MOQT relay authorize sessions and requests with Common Access Tokens, as
// draft-ietf-moq-c4m describes, over draft-ietf-moq-transport-22, with no MOQT library underneath (decision 0039).
//
// A relay keeps one Session for each MOQT session it accepts. For SETUP and for each request that may carry
// authorization (SUBSCRIBE, FETCH, PUBLISH, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS, TRACK_STATUS
// and REQUEST_UPDATE), it passes Authorize the action, the Track Namespace and Track Name, and the value of each
// AUTHORIZATION TOKEN parameter or Setup Option, as its MOQT stack parsed them. Authorize applies each Token
// structure to the session's token cache (REGISTER, USE_ALIAS, DELETE or USE_VALUE), judges every CAT (Token Type
// 0x01) with package cat, and returns a Grant, or an *Error that says whether to refuse the request with
// REQUEST_ERROR or to close the session, and with which of draft 22's codes.
//
// A Grant reports the token's moqt-reval interval. Revalidating is the relay's: it calls Grant.Recheck at least
// that often while the subscription lasts, and ends it when Recheck fails.
//
// # Where things are
//
// Each source file's tests are in the test file of the same name; tests that need the package's internals are in
// the matching _internal_test.go file.
//
//	session.go  Session, Request, Grant and Authorize: the token cache and judging
//	errors.go   Error and the MOQT error codes
//	token.go    the Token structure (draft 22, "Authorization Token Compression")
//	varint.go   draft 22's variable-length integers
package catmoqt
