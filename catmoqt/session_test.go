package catmoqt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/catmoqt"
	"github.com/terra-howard/wtcat/cwt"
)

var (
	secret  = []byte("0123456789abcdef0123456789abcdef")
	testNow = time.Unix(1700000000, 0)
	moqtKey = int64(cat.DefaultMOQTClaimKey)
)

// vi encodes n in draft-ietf-moq-transport-22's variable-length form, in the shortest length unless pad asks for
// more bytes. It is written here apart from the package's decoder.
func vi(n uint64, pad ...int) []byte {
	length := 1
	for length < 9 && (length == 8 && n >= 1<<56 || length < 8 && n >= 1<<(7*length)) {
		length++
	}
	if len(pad) > 0 {
		length = pad[0]
	}
	b := make([]byte, length)
	v := n
	for i := length - 1; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	if length < 9 {
		b[0] |= byte(0xff << (9 - length)) // the leading ones, then a zero
	} else {
		b[0] = 0xff
	}
	return b
}

func cat2(b ...[]byte) []byte {
	var out []byte
	for _, x := range b {
		out = append(out, x...)
	}
	return out
}

// The four Alias Types of a Token structure (draft 22, section "Authorization Token Compression").
func deleteAlias(alias uint64) []byte                 { return cat2(vi(0), vi(alias)) }
func register(alias, typ uint64, value []byte) []byte { return cat2(vi(1), vi(alias), vi(typ), value) }
func useAlias(alias uint64) []byte                    { return cat2(vi(2), vi(alias)) }
func useValue(typ uint64, value []byte) []byte        { return cat2(vi(3), vi(typ), value) }

// token issues an HMAC CAT with the given claims, allowing every MOQT action unless the claims set moqt themselves.
func token(t *testing.T, claims map[any]any) []byte {
	t.Helper()
	all := map[any]any{moqtKey: map[any]any{0: []any{[]any{[]any{1, 2, 3, 4, 5, 6, 7, 8, 9}}}}}
	for k, v := range claims {
		all[k] = v
	}
	payload, err := cbor.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cwt.Issue(payload, cwt.SigningKey{Algorithm: cwt.HMAC256x256, Material: secret})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func session() *catmoqt.Session {
	return &catmoqt.Session{
		Validator: &cat.Validator{
			Keys: func([]byte) (cat.Key, error) {
				return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: secret}}, nil
			},
			Now: func() time.Time { return testNow },
		},
		MaxCacheSize: 4096,
	}
}

func subscribe(tokens ...[]byte) catmoqt.Request {
	return catmoqt.Request{Action: cat.MOQTSubscribe, Namespace: [][]byte{[]byte("cdn")}, Track: []byte("t"), Tokens: tokens}
}

func setup(tokens ...[]byte) catmoqt.Request {
	return catmoqt.Request{Action: cat.MOQTSetup, Tokens: tokens}
}

// refusal is what a refused request must report: a session code when session is true, else a REQUEST_ERROR code.
type refusal struct {
	session bool
	code    catmoqt.Code
}

var granted = refusal{}

func check(t *testing.T, s *catmoqt.Session, r catmoqt.Request, want refusal) *catmoqt.Grant {
	t.Helper()
	g, err := s.Authorize(r)
	if want == granted {
		if err != nil || g == nil {
			t.Fatalf("refused: %v", err)
		}
		return g
	}
	var e *catmoqt.Error
	if !errors.As(err, &e) {
		t.Fatalf("got %v, %v; want a refusal %+v", g, err, want)
	}
	if e.Session != want.session || e.Code != want.code {
		t.Fatalf("got session %v code %#x (%v); want session %v code %#x", e.Session, uint64(e.Code), err, want.session, uint64(want.code))
	}
	if g != nil {
		t.Fatalf("a refusal came with a grant")
	}
	return nil
}

var (
	unauthorized   = refusal{false, catmoqt.RequestUnauthorized}
	malformedReq   = refusal{false, catmoqt.RequestMalformedAuthToken}
	expiredReq     = refusal{false, catmoqt.RequestExpiredAuthToken}
	unknownAlias   = refusal{true, catmoqt.SessionUnknownAuthTokenAlias}
	duplicateAlias = refusal{true, catmoqt.SessionDuplicateAuthTokenAlias}
	overflow       = refusal{true, catmoqt.SessionAuthTokenCacheOverflow}
	formatting     = refusal{true, catmoqt.SessionKeyValueFormattingError}
	violation      = refusal{true, catmoqt.SessionProtocolViolation}
)

func TestTokenCache(t *testing.T) {
	good := token(t, nil)
	expired := token(t, map[any]any{4: testNow.Unix() - 1})
	t.Run("a token used by value", func(t *testing.T) { check(t, session(), subscribe(useValue(catmoqt.TokenTypeCAT, good)), granted) })
	t.Run("no token", func(t *testing.T) { check(t, session(), subscribe(), unauthorized) })
	t.Run("only a token of another type", func(t *testing.T) { check(t, session(), subscribe(useValue(7, good)), unauthorized) })
	t.Run("register, then use the alias", func(t *testing.T) {
		s := session()
		check(t, s, subscribe(register(1, catmoqt.TokenTypeCAT, good)), granted)
		check(t, s, subscribe(useAlias(1)), granted)
	})
	t.Run("a repeated REGISTER", func(t *testing.T) {
		s := session()
		check(t, s, subscribe(register(1, catmoqt.TokenTypeCAT, good)), granted)
		check(t, s, subscribe(register(1, catmoqt.TokenTypeCAT, good)), duplicateAlias)
	})
	t.Run("an unknown alias", func(t *testing.T) { check(t, session(), subscribe(useAlias(1)), unknownAlias) })
	t.Run("a DELETE of an unknown alias", func(t *testing.T) { check(t, session(), subscribe(deleteAlias(1), useValue(1, good)), unknownAlias) })
	t.Run("an alias after its DELETE", func(t *testing.T) {
		s := session()
		check(t, s, subscribe(register(1, catmoqt.TokenTypeCAT, good)), granted)
		check(t, s, subscribe(deleteAlias(1), useValue(catmoqt.TokenTypeCAT, good)), granted)
		check(t, s, subscribe(useAlias(1)), unknownAlias)
	})
	t.Run("a REGISTER in a refused message still registers", func(t *testing.T) {
		s := session()
		check(t, s, subscribe(register(1, catmoqt.TokenTypeCAT, expired)), expiredReq)
		check(t, s, subscribe(useAlias(1)), expiredReq) // known, so not UNKNOWN_AUTH_TOKEN_ALIAS
	})
	t.Run("the cache limit counts 16 bytes and the value", func(t *testing.T) {
		s := session()
		s.MaxCacheSize = uint64(2 * (16 + len(good)))
		check(t, s, subscribe(register(1, catmoqt.TokenTypeCAT, good)), granted)
		check(t, s, subscribe(register(2, catmoqt.TokenTypeCAT, good)), granted) // exactly at the limit
		check(t, s, subscribe(register(3, catmoqt.TokenTypeCAT, good)), overflow)
	})
	t.Run("a DELETE frees its space", func(t *testing.T) {
		s := session()
		s.MaxCacheSize = uint64(16 + len(good))
		check(t, s, subscribe(register(1, catmoqt.TokenTypeCAT, good)), granted)
		check(t, s, subscribe(deleteAlias(1), register(2, catmoqt.TokenTypeCAT, good)), granted)
		check(t, s, subscribe(useAlias(2)), granted)
	})
	t.Run("the default limit of 0 allows no alias", func(t *testing.T) {
		s := session()
		s.MaxCacheSize = 0
		check(t, s, subscribe(register(1, catmoqt.TokenTypeCAT, good)), overflow)
	})
	t.Run("a REGISTER past the limit in SETUP is used by value", func(t *testing.T) {
		s := session()
		s.MaxCacheSize = 0
		check(t, s, setup(register(1, catmoqt.TokenTypeCAT, good)), granted)
		check(t, s, subscribe(useAlias(1)), unknownAlias)
	})
	t.Run("a REGISTER in SETUP within the limit", func(t *testing.T) {
		s := session()
		check(t, s, setup(register(1, catmoqt.TokenTypeCAT, good)), granted)
		check(t, s, subscribe(useAlias(1)), granted)
	})
	t.Run("DELETE in SETUP", func(t *testing.T) { check(t, session(), setup(deleteAlias(1), useValue(1, good)), violation) })
	t.Run("USE_ALIAS in SETUP", func(t *testing.T) {
		s := session()
		check(t, s, setup(register(1, catmoqt.TokenTypeCAT, good), useAlias(1)), violation)
	})
	t.Run("a token repeated after resolving its alias", func(t *testing.T) {
		s := session()
		check(t, s, subscribe(register(1, catmoqt.TokenTypeCAT, good)), granted)
		check(t, s, subscribe(useAlias(1), useValue(catmoqt.TokenTypeCAT, good)), malformedReq)
	})
	t.Run("a token repeated in SETUP", func(t *testing.T) {
		check(t, session(), setup(useValue(1, good), useValue(1, good)), refusal{true, catmoqt.SessionMalformedAuthToken})
	})
	t.Run("the same value under two types is no repeat", func(t *testing.T) {
		check(t, session(), subscribe(useValue(7, good), useValue(catmoqt.TokenTypeCAT, good)), granted)
	})
	t.Run("longer integer encodings", func(t *testing.T) {
		check(t, session(), subscribe(cat2(vi(3, 4), vi(catmoqt.TokenTypeCAT, 9), good)), granted)
	})
	t.Run("Lookup returns a registered token of any type", func(t *testing.T) {
		s := session()
		check(t, s, subscribe(register(5, 7, []byte("other")), useValue(1, good)), granted)
		if tok, ok := s.Lookup(5); !ok || tok.Type != 7 || string(tok.Value) != "other" {
			t.Fatalf("Lookup(5) = %+v, %v", tok, ok)
		}
		if _, ok := s.Lookup(6); ok {
			t.Fatal("Lookup(6) found an alias never registered")
		}
	})
}

func TestTokenStructureSyntax(t *testing.T) {
	good := token(t, nil)
	for name, raw := range map[string][]byte{
		"empty":                     {},
		"an unknown Alias Type":     cat2(vi(4), vi(1)),
		"a truncated Alias Type":    {0x80},
		"DELETE without an alias":   vi(0),
		"DELETE with more after":    cat2(deleteAlias(1), []byte{0}),
		"USE_ALIAS with more after": cat2(useAlias(1), []byte{0}),
		"REGISTER without a type":   cat2(vi(1), vi(1)),
		"USE_VALUE without a type":  vi(3),
		"a truncated alias":         cat2(vi(2), []byte{0xc0}),
	} {
		t.Run(name, func(t *testing.T) { check(t, session(), subscribe(raw, useValue(1, good)), formatting) })
	}
}

func TestRefusalCodes(t *testing.T) {
	good := token(t, nil)
	expired := token(t, map[any]any{4: testNow.Unix() - 1})
	narrow := token(t, map[any]any{moqtKey: map[any]any{0: []any{[]any{[]any{1}}}}}) // SETUP only
	for _, tc := range []struct {
		name string
		r    catmoqt.Request
		want refusal
	}{
		{"an expired token", subscribe(useValue(1, expired)), expiredReq},
		{"a value that is no CAT", subscribe(useValue(1, []byte{0x01, 0x02})), malformedReq},
		{"a token for other actions", subscribe(useValue(1, narrow)), unauthorized},
		{"SETUP with an expired token", setup(useValue(1, expired)), refusal{true, catmoqt.SessionExpiredAuthToken}},
		{"SETUP with a value that is no CAT", setup(useValue(1, []byte{0x01})), refusal{true, catmoqt.SessionMalformedAuthToken}},
		{"SETUP with no token", setup(), refusal{true, catmoqt.SessionUnauthorized}},
		{"SETUP with a token for other actions", setup(useValue(1, token(t, map[any]any{moqtKey: map[any]any{0: []any{[]any{[]any{4}}}}}))), refusal{true, catmoqt.SessionUnauthorized}},
		{"the first acceptable token grants", subscribe(useValue(1, narrow), useValue(1, good)), granted},
		{"refused, named after the first token", subscribe(useValue(1, expired), useValue(1, narrow)), expiredReq},
		{"refused, named after the first token, again", subscribe(useValue(1, narrow), useValue(1, expired)), unauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, session(), tc.r, tc.want) })
	}
}

// TestC4MAuthorizationScopes runs draft-ietf-moq-c4m's "MOQT Authorization Scopes" vectors through a Session, each
// token sent by value (the vectors are cat's fixtures; see cat/testdata/c4m/SOURCE.md).
func TestC4MAuthorizationScopes(t *testing.T) {
	raw, err := os.ReadFile("../cat/testdata/c4m/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keys struct {
			HMAC string `json:"hmac_sha256"`
		} `json:"keys"`
		Scopes []struct {
			ID      string `json:"id"`
			CoseB64 string `json:"cose_b64"`
			Tests   []struct {
				Action    int      `json:"action"`
				Namespace []string `json:"namespace"`
				Track     *string  `json:"track"`
				Expected  bool     `json:"expected"`
			} `json:"authorization_tests"`
		} `json:"moqt_authorization_scopes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(v.Keys.HMAC)
	if err != nil {
		t.Fatal(err)
	}
	s := &catmoqt.Session{Validator: &cat.Validator{
		Keys: func([]byte) (cat.Key, error) {
			return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: key}, Issuer: "https://auth.example.com"}, nil
		},
		Now:             func() time.Time { return time.Unix(1700003600, 0) },
		MinRevalidation: time.Minute,
	}}
	n := 0
	for _, vec := range v.Scopes {
		tok, err := base64.RawURLEncoding.DecodeString(vec.CoseB64)
		if err != nil {
			t.Fatal(err)
		}
		for i, tc := range vec.Tests {
			r := catmoqt.Request{Action: tc.Action, Tokens: [][]byte{useValue(catmoqt.TokenTypeCAT, tok)}}
			for _, f := range tc.Namespace {
				r.Namespace = append(r.Namespace, []byte(f))
			}
			if tc.Track != nil {
				r.Track = []byte(*tc.Track)
			}
			want := unauthorized
			if tc.Expected {
				want = granted
			}
			if tc.Action == cat.MOQTSetup && !tc.Expected {
				want = refusal{true, catmoqt.SessionUnauthorized}
			}
			t.Run(fmt.Sprintf("%s/%d", vec.ID, i), func(t *testing.T) { check(t, s, r, want) })
			n++
		}
	}
	if n != 19 {
		t.Fatalf("%d authorization tests, want the draft's 19", n)
	}
}

// TestClientFacts checks that the session's client facts reach cat: its connection's ID binds catreplay (decision
// 0037).
func TestClientFacts(t *testing.T) {
	bound := map[string]string{}
	var mu sync.Mutex
	bind := func(cti []byte, connection string, _ time.Time) bool {
		mu.Lock()
		defer mu.Unlock()
		if c, ok := bound[string(cti)]; ok {
			return c != connection
		}
		bound[string(cti)] = connection
		return false
	}
	tok := token(t, map[any]any{7: []byte{1}, 4: testNow.Unix() + 60, 308: 1})
	on := func(id string) *catmoqt.Session {
		s := session()
		s.Validator.BindConnection = bind
		s.Client.Connection = &cat.Connection{ID: id}
		return s
	}
	a, b := on("a"), on("b")
	check(t, a, subscribe(useValue(1, tok)), granted)
	check(t, a, subscribe(useValue(1, tok)), granted)
	check(t, b, subscribe(useValue(1, tok)), unauthorized)
}

// TestGrantRevalidation checks a grant's moqt-reval interval and Recheck (decision 0036).
func TestGrantRevalidation(t *testing.T) {
	s := session()
	s.Validator.MinRevalidation = time.Second
	now := testNow
	s.Validator.Now = func() time.Time { return now }
	g := check(t, s, subscribe(useValue(1, token(t, map[any]any{4: testNow.Unix() + 100, int64(cat.DefaultMOQTRevalKey): 30}))), granted)
	if g.Revalidate != 30*time.Second || g.Token == nil {
		t.Fatalf("Revalidate = %v, Token = %v", g.Revalidate, g.Token)
	}
	if err := g.Recheck(); err != nil {
		t.Fatalf("Recheck before exp: %v", err)
	}
	now = testNow.Add(100 * time.Second)
	if err := g.Recheck(); !errors.Is(err, cat.ErrExpired) {
		t.Fatalf("Recheck at exp: got %v, want cat.ErrExpired", err)
	}
}

// TestDPoPThroughASession checks that a request's proof reaches cat: a token bound by ckt is granted with a good
// proof, and refused without one (decision 0038).
func TestDPoPThroughASession(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	coseKey := map[int64]any{1: 2, -1: 1, -2: pt[1:33], -3: pt[33:]}
	sorted, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	encKey, err := sorted.Marshal(coseKey)
	if err != nil {
		t.Fatal(err)
	}
	ckt := sha256.Sum256(encKey)
	tok := token(t, map[any]any{8: map[any]any{5: ckt[:]}})
	const actxKey, athKey = -70001, -70002
	ath := sha256.Sum256(tok)
	protected, _ := cbor.Marshal(map[int64]any{1: -7, 16: "dpop-proof+cwt", 14: map[int64]any{8: map[int64]any{1: coseKey}}})
	payload, _ := cbor.Marshal(map[int64]any{7: []byte("p1"), 6: testNow.Unix(), athKey: ath[:],
		actxKey: map[int64]any{0: "moqt", 1: cat.MOQTSubscribe, 2: []any{[]byte("cdn")}, 3: []byte("t")}})
	toBeSigned, _ := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	digest := sha256.Sum256(toBeSigned)
	r, sv, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	proof, _ := cbor.Marshal(cbor.Tag{Number: 18, Content: []any{protected, map[int64]any{}, payload, sig}})

	s := session()
	s.Validator.ActxKey, s.Validator.AthKey = actxKey, athKey
	req := subscribe(useValue(1, tok))
	check(t, s, req, unauthorized)
	req.Proof = proof
	check(t, s, req, granted)
}

// TestConcurrentSession registers and uses aliases from many goroutines at once. Run with -race.
func TestConcurrentSession(t *testing.T) {
	s := session()
	s.MaxCacheSize = 1 << 20
	good := token(t, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 32 {
		wg.Add(1)
		go func(alias uint64) {
			defer wg.Done()
			if _, err := s.Authorize(subscribe(register(alias, 1, good))); err != nil {
				errs <- err
				return
			}
			if _, err := s.Authorize(subscribe(useAlias(alias))); err != nil {
				errs <- err
			}
		}(uint64(i))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
