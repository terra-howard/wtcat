// Package cathttp protects HTTP handlers with Common Access Tokens: it finds the tokens in a request, checks them
// with package cat, and applies what the accepted token asks of the response (decision 0019).
//
// An Authorizer wraps a cat.Validator with the facts a request supplies: the request URI each token is judged
// with, the client's address, the TLS connection, and, through options, anything a proxy in front hides. Its
// Middleware passes a request with an acceptable token to the handler and answers any other with 401, or with the
// response a refused token's catif asks for. Every response to a request that carried a token is marked private,
// renewals under catr are added as cookies, header fields or redirects, and the token-bearing fields are removed
// before the request is forwarded. Authorize does the judging alone, for callers that respond themselves.
//
// Section numbers refer to CTA-5007-B. Section 4.4 sets where tokens may be and in what order they are judged: if
// the CTA-Common-Access-Token field (or a configured one) is present, nothing else is read; otherwise path-style
// and form-style parameters are read left to right, then cookies, then the authorization field. Find returns them
// in that order, and RemoveFromURI applies section 4.6.10's rule for taking a token out of the URI before catu.
//
// # Where things are
//
// Each source file's tests are in the test file of the same name; tests that need the package's internals are in
// the matching _internal_test.go file.
//
//	authorize.go  Authorizer: judging a request's tokens, and the middleware (401, Cache-Control private, stripping)
//	renew.go      applying catr renewals: cookie, header or redirect (decision 0022)
//	locate.go     Find, Place, Located, Options and RemoveFromURI (section 4.6.10's removal rule)
//	field.go      the Structured Field item parser for the token field (RFC 9651)
//
//	example_test.go  ExampleAuthorizer_Middleware, checked by go test
package cathttp
