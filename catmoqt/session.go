package catmoqt

import (
	"encoding/base64"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

// entrySize is what a registered token counts against the cache limit beyond its value (draft 22,
// "MAX_AUTH_TOKEN_CACHE_SIZE").
const entrySize = 16

// Session is the authorization state of one MOQT session, on the side that receives tokens: a relay. Its methods
// are safe for concurrent use, since each request of a session arrives on its own stream.
type Session struct {
	Validator *cat.Validator // required
	// Client holds what is known of the client and its connection for every request of the session: ClientIP and
	// ClientASN for catnip, Location for the geographic claims, and Connection for catalpn, cattpk and, by its ID,
	// catreplay (decision 0037). Its MOQT field is set for each request.
	Client cat.Request
	// MaxCacheSize is the MAX_AUTH_TOKEN_CACHE_SIZE this endpoint sent in its SETUP: the bytes of registered tokens
	// it will hold, each counting 16 bytes and its value. Zero, the draft's default, allows no aliases.
	MaxCacheSize uint64

	mu    sync.Mutex
	cache map[uint64]Token
	size  uint64
}

// Request is one MOQT message to authorize: SETUP, or a request that may carry an AUTHORIZATION TOKEN parameter.
type Request struct {
	Action    int      // the draft-ietf-moq-c4m action, cat.MOQTSetup to cat.MOQTSubscribeTracks
	Namespace [][]byte // the Track Namespace fields, for an action that names one
	Track     []byte   // the Track Name, for an action that names one; nil when it names none
	// Tokens holds the value of each AUTHORIZATION TOKEN parameter, or Setup Option for SETUP, in message order:
	// a Token structure each.
	Tokens [][]byte
	// Proof is the DPoP proof sent with the action, for a token bound by cnf. draft-ietf-moq-c4m does not yet say
	// how a proof travels, so the caller supplies it however it arrived (decision 0039).
	Proof []byte
}

// Grant is an authorized request.
type Grant struct {
	Token *cat.Token // the CAT that granted it
	// Revalidate is how often the relay must call Recheck while what the request started continues, counting from
	// the last success, from the token's moqt-reval (decision 0036). Zero means never.
	Revalidate time.Duration

	validator *cat.Validator
	text      string
	req       cat.Request
}

// Recheck validates the grant's token against the same request again. When it fails, the relay ends what the
// request started: for a subscription, PUBLISH_DONE with UNAUTHORIZED, or a stream reset with EXPIRED_AUTH_TOKEN
// when errors.Is(err, cat.ErrExpired).
func (g *Grant) Recheck() error {
	req := g.req
	again := *req.MOQT
	again.Revalidating = true // the token is judged again, not the proof that came with the request (decision 0039)
	req.MOQT = &again
	_, err := g.validator.ValidateRequest(g.text, &req)
	return err
}

// Lookup returns the token registered under alias, of whatever type.
func (s *Session) Lookup(alias uint64) (Token, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.cache[alias]
	return t, ok
}

// Authorize applies the request's Token structures to the session's cache, then grants the request by the first
// CAT among them that is acceptable for its action. A refusal is an *Error.
func (s *Session) Authorize(r Request) (*Grant, error) {
	setup := r.Action == cat.MOQTSetup
	tokens, err := s.resolve(r.Tokens, setup)
	if err != nil {
		return nil, err
	}
	req := s.Client
	req.MOQT = &cat.MOQTAction{Action: r.Action, Namespace: r.Namespace, Track: r.Track, Proof: r.Proof}
	var first error
	for i, t := range tokens {
		if slices.ContainsFunc(tokens[:i], func(u Token) bool { return u.Type == t.Type && string(u.Value) == string(t.Value) }) {
			return nil, refuse(setup, RequestMalformedAuthToken, SessionMalformedAuthToken, errors.New("a token repeated in one message"))
		}
	}
	for _, t := range tokens {
		if t.Type != TokenTypeCAT {
			continue
		}
		text := base64.RawURLEncoding.EncodeToString(t.Value)
		tok, err := s.Validator.ValidateRequest(text, &req)
		if err == nil {
			return &Grant{Token: tok, Revalidate: tok.Revalidate, validator: s.Validator, text: text, req: req}, nil
		}
		if first == nil {
			first = err
		}
	}
	if first == nil {
		return nil, refuse(setup, RequestUnauthorized, SessionUnauthorized, errors.New("no CAT authorizes the action"))
	}
	switch {
	case errors.Is(first, cat.ErrExpired):
		return nil, refuse(setup, RequestExpiredAuthToken, SessionExpiredAuthToken, first)
	case errors.Is(first, cwt.ErrMalformed):
		return nil, refuse(setup, RequestMalformedAuthToken, SessionMalformedAuthToken, first)
	}
	return nil, refuse(setup, RequestUnauthorized, SessionUnauthorized, first)
}

// refuse is a refused request, or for SETUP a refused session.
func refuse(setup bool, request, session Code, err error) *Error {
	if setup {
		return &Error{Session: true, Code: session, Err: err}
	}
	return &Error{Code: request, Err: err}
}

// resolve applies a message's Token structures to the cache, as one step, and returns the tokens they name.
func (s *Session) resolve(raw [][]byte, setup bool) ([]Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[uint64]Token{}
	}
	var tokens []Token
	for _, b := range raw {
		t, err := parseToken(b)
		if err != nil {
			return nil, sessionError(SessionKeyValueFormattingError, "a Token structure that cannot be decoded: %v", err)
		}
		if setup && (t.aliasType == aliasDelete || t.aliasType == aliasUse) {
			return nil, sessionError(SessionProtocolViolation, "DELETE or USE_ALIAS in SETUP")
		}
		known, registered := s.cache[t.alias]
		byAlias := t.aliasType == aliasDelete || t.aliasType == aliasUse
		if byAlias && !registered {
			return nil, sessionError(SessionUnknownAuthTokenAlias, "alias %d is not registered", t.alias)
		}
		if t.aliasType == aliasRegister && registered {
			return nil, sessionError(SessionDuplicateAuthTokenAlias, "alias %d is already registered", t.alias)
		}
		switch t.aliasType {
		case aliasDelete:
			delete(s.cache, t.alias)
			s.size -= entrySize + uint64(len(known.Value))
		case aliasUse:
			tokens = append(tokens, known)
		case aliasRegister:
			need := entrySize + uint64(len(t.token.Value))
			// In this order, so that neither subtraction wraps, even should the limit be lowered.
			fits := need <= s.MaxCacheSize && s.size <= s.MaxCacheSize-need
			if fits {
				s.cache[t.alias] = Token{Type: t.token.Type, Value: slices.Clone(t.token.Value)}
				s.size += need
			} else if !setup {
				return nil, sessionError(SessionAuthTokenCacheOverflow, "registering alias %d would pass the cache limit of %d bytes", t.alias, s.MaxCacheSize)
			} // in SETUP, a REGISTER past the limit is used by value
			tokens = append(tokens, t.token)
		default:
			tokens = append(tokens, t.token)
		}
	}
	return tokens, nil
}
