package catmoqt

import "fmt"

// Code is a draft-ietf-moq-transport-22 error code: a REQUEST_ERROR code or a session termination code, as
// Error.Session says.
type Code uint64

// The REQUEST_ERROR codes a refused request is given.
const (
	RequestUnauthorized       Code = 0x1
	RequestMalformedAuthToken Code = 0x4
	RequestExpiredAuthToken   Code = 0x5
)

// The session termination codes for a refused SETUP and for errors in the token cache.
const (
	SessionUnauthorized            Code = 0x2
	SessionProtocolViolation       Code = 0x3
	SessionKeyValueFormattingError Code = 0x6
	SessionAuthTokenCacheOverflow  Code = 0x13
	SessionDuplicateAuthTokenAlias Code = 0x14
	SessionMalformedAuthToken      Code = 0x16
	SessionUnknownAuthTokenAlias   Code = 0x17
	SessionExpiredAuthToken        Code = 0x18
)

// Error is a refusal. When Session is true the relay closes the session with Code; otherwise it refuses the
// request with REQUEST_ERROR and Code. Err says why, and is a cat error when a token was judged.
type Error struct {
	Session bool
	Code    Code
	Err     error
}

func (e *Error) Error() string {
	kind := "request refused"
	if e.Session {
		kind = "session closed"
	}
	return fmt.Sprintf("catmoqt: %s with code %#x: %v", kind, uint64(e.Code), e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func sessionError(code Code, format string, args ...any) *Error {
	return &Error{Session: true, Code: code, Err: fmt.Errorf(format, args...)}
}
