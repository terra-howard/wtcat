// Package cathttp finds Common Access Tokens in HTTP requests and checks them with package cat (decision 0019).
//
// Section numbers refer to CTA-5007-B. Section 4.4 sets where tokens may be and in what order they are judged: if
// the CTA-Common-Access-Token field (or a configured one) is present, nothing else is read; otherwise path-style
// and form-style parameters are read left to right, then cookies, then the authorization field.
//
// Where things are. Each source file's tests are in the test file of the same name.
//
//	locate.go  Find, Located, Options and RemoveFromURI (section 4.6.10's removal rule)
//	field.go   the Structured Field item parser for the token field (RFC 9651)
package cathttp
