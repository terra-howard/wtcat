package cat_test

import (
	"errors"
	"testing"
	"time"

	"github.com/terra-howard/wtcat/cat"
)

// bindings is a BindConnection store backed by a map, recording its calls.
type bindings struct {
	bound map[string]string
	calls int
	until time.Time
}

func (b *bindings) bind(cti []byte, connection string, until time.Time) (elsewhere bool) {
	b.calls++
	b.until = until
	if b.bound == nil {
		b.bound = map[string]string{}
	}
	if c, ok := b.bound[string(cti)]; ok {
		return c != connection
	}
	b.bound[string(cti)] = connection
	return false
}

var replayExp = testNow.Add(time.Hour)

// replayToken is a token allowing MOQT action 4 anywhere, with the given extra claims.
func replayToken(t *testing.T, extra map[any]any) string {
	claims := map[any]any{moqtKey: map[any]any{0: []any{[]any{[]any{4}}}}}
	for k, v := range extra {
		claims[k] = v
	}
	return claimsToken(t, claims)
}

func onConnection(action int, id string) *cat.Request {
	r := moqtRequest(action, []string{"a"}, text("t"))
	r.Connection = &cat.Connection{ID: id}
	return r
}

func bindingValidator(b *bindings) *cat.Validator {
	v := validator()
	v.BindConnection = b.bind
	v.Replay = func([]byte) bool { panic("Replay called for a MOQT request") }
	return v
}

// TestCatreplayBindsAMOQTConnection checks decision 0037: over MOQT, catreplay 1 (and 2, and values above, read as 1)
// accepts a token any number of times on the connection that first presented it, and refuses it on any other.
func TestCatreplayBindsAMOQTConnection(t *testing.T) {
	for _, value := range []int{1, 2, 7} {
		b := &bindings{}
		token := replayToken(t, map[any]any{7: []byte{1}, 4: replayExp.Unix(), 308: value})
		v := bindingValidator(b)
		for i := range 3 {
			if _, err := v.ValidateRequest(token, onConnection(4, "c1")); err != nil {
				t.Fatalf("catreplay %d, use %d on the first connection: %v", value, i+1, err)
			}
		}
		_, err := v.ValidateRequest(token, onConnection(4, "c2"))
		wantKind(t, err, cat.ErrReplay)
		if b.calls != 4 {
			t.Errorf("catreplay %d: BindConnection called %d times, want 4", value, b.calls)
		}
		if !b.until.Equal(replayExp) {
			t.Errorf("catreplay %d: until = %v, want the token's exp %v", value, b.until, replayExp)
		}
	}
}

func TestCatreplayOverMOQTRules(t *testing.T) {
	withBoth := map[any]any{7: []byte{1}, 4: replayExp.Unix(), 308: 1}
	cases := []struct {
		name    string
		claims  map[any]any
		hook    bool
		req     *cat.Request
		want    error
		binding bool // whether BindConnection must be called
	}{
		{"catreplay 0 binds nothing", map[any]any{7: []byte{1}, 4: replayExp.Unix(), 308: 0}, true, onConnection(4, "c1"), nil, false},
		{"no catreplay binds nothing", map[any]any{7: []byte{1}, 4: replayExp.Unix()}, true, onConnection(4, "c1"), nil, false},
		{"no cti is refused", map[any]any{4: replayExp.Unix(), 308: 1}, true, onConnection(4, "c1"), cat.ErrReplay, false},
		{"no exp is refused", map[any]any{7: []byte{1}, 308: 1}, true, onConnection(4, "c1"), cat.ErrReplay, false},
		{"no cti is refused without the hook too", map[any]any{4: replayExp.Unix(), 308: 2}, false, onConnection(4, "c1"), cat.ErrReplay, false},
		{"no exp is refused without the hook too", map[any]any{7: []byte{1}, 308: 1}, false, onConnection(4, "c1"), cat.ErrReplay, false},
		{"without the hook it is not enforced", withBoth, false, onConnection(4, "c1"), nil, false},
		{"with the hook and no connection", withBoth, true, moqtRequest(4, []string{"a"}, text("t")), cat.ErrReplay, false},
		{"with the hook and an empty connection ID", withBoth, true, onConnection(4, ""), cat.ErrReplay, false},
		{"a token refused for its action never binds", withBoth, true, onConnection(6, "c1"), cat.ErrMOQT, false},
		{"a token bound to nothing yet binds", withBoth, true, onConnection(4, "c1"), nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &bindings{}
			v := validator()
			v.Replay = func([]byte) bool { panic("Replay called for a MOQT request") }
			if tc.hook {
				v.BindConnection = b.bind
			}
			_, err := v.ValidateRequest(replayToken(t, tc.claims), tc.req)
			if tc.want == nil && err != nil {
				t.Fatalf("ValidateRequest: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if called := b.calls > 0; called != tc.binding {
				t.Errorf("BindConnection called: %v, want %v", called, tc.binding)
			}
		})
	}
}

// TestBindConnectionKeepsAFractionalExp checks that a binding is kept to the token's exp exactly, fraction included.
func TestBindConnectionKeepsAFractionalExp(t *testing.T) {
	b := &bindings{}
	exp := float64(replayExp.Unix()) + 0.5
	token := replayToken(t, map[any]any{7: []byte{1}, 4: exp, 308: 1})
	if _, err := bindingValidator(b).ValidateRequest(token, onConnection(4, "c1")); err != nil {
		t.Fatalf("ValidateRequest: %v", err)
	}
	if want := replayExp.Add(500 * time.Millisecond); !b.until.Equal(want) {
		t.Fatalf("until = %v, want %v", b.until, want)
	}
}

// TestCatreplayOverHTTPIsUnchanged checks that an HTTP request uses Replay, never BindConnection, and keeps decision
// 0021's single use, even for a token that also carries the moqt claim.
func TestCatreplayOverHTTPIsUnchanged(t *testing.T) {
	m := &memory{}
	v := validator()
	v.Replay = m.replay
	v.BindConnection = func([]byte, string, time.Time) bool { panic("BindConnection called for an HTTP request") }
	token := replayToken(t, map[any]any{7: []byte{1}, 4: replayExp.Unix(), 308: 1})
	if _, err := v.ValidateRequest(token, get()); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err := v.ValidateRequest(token, get())
	wantKind(t, err, cat.ErrReplay)
	// Over HTTP, catreplay without a cti is still accepted (decision 0021).
	if _, err := v.ValidateRequest(replayToken(t, map[any]any{308: 1}), get()); err != nil {
		t.Fatalf("HTTP, no cti: %v", err)
	}
}
