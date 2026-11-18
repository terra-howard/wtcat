package cat_test

import (
	"sync"
	"testing"

	"github.com/terra-howard/wtcat/cat"
)

// memory is a Replay function backed by a map, counting its calls.
type memory struct {
	seen  map[string]bool
	calls int
}

func (m *memory) replay(cti []byte) bool {
	m.calls++
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	was := m.seen[string(cti)]
	m.seen[string(cti)] = true
	return was
}

func replayValidator(m *memory) *cat.Validator {
	v := validator()
	v.Replay = m.replay
	return v
}

func TestCatreplayRefusesReuse(t *testing.T) {
	for _, value := range []int{1, 2, 7} {
		m := &memory{}
		token := claimsToken(t, map[any]any{7: []byte{1}, 308: value})
		if _, err := replayValidator(m).Validate(token); err != nil {
			t.Fatalf("catreplay %d, first use: %v", value, err)
		}
		_, err := replayValidator(m).Validate(token)
		wantKind(t, err, cat.ErrReplay)
		wantKind(t, err, cat.ErrUnacceptable)
	}
}

func TestCatreplayZeroNeverRefusesAndNeverAsks(t *testing.T) {
	m := &memory{}
	token := claimsToken(t, map[any]any{7: []byte{1}, 308: 0})
	for i := range 2 {
		if _, err := replayValidator(m).Validate(token); err != nil {
			t.Fatalf("use %d: %v", i+1, err)
		}
	}
	if m.calls != 0 {
		t.Errorf("Replay was called %d times for catreplay 0", m.calls)
	}
}

func TestCatreplayNeedsACtiAndAReplayFunction(t *testing.T) {
	m := &memory{}
	noCti := claimsToken(t, map[any]any{308: 1})
	for i := range 2 {
		if _, err := replayValidator(m).Validate(noCti); err != nil {
			t.Fatalf("no cti, use %d: %v", i+1, err)
		}
	}
	if m.calls != 0 {
		t.Errorf("Replay was called without a cti")
	}
	withCti := claimsToken(t, map[any]any{7: []byte{1}, 308: 1})
	for i := range 2 {
		if _, err := validator().Validate(withCti); err != nil {
			t.Fatalf("no Replay function, use %d: %v", i+1, err)
		}
	}
}

// A token refused for another reason does not use up its cti.
func TestCatreplayIsCheckedLast(t *testing.T) {
	m := &memory{}
	expired := claimsToken(t, map[any]any{4: 1699999999, 7: []byte{9}, 308: 1})
	_, err := replayValidator(m).Validate(expired)
	wantKind(t, err, cat.ErrExpired)
	if _, err := replayValidator(m).Validate(claimsToken(t, map[any]any{7: []byte{9}, 308: 1})); err != nil {
		t.Fatalf("a fresh token with the refused token's cti: %v", err)
	}
}

// TestCatreplayConcurrentUseAcceptsOnce is decision 0032's OneConnection invariant for single use over HTTP: with an
// atomic Replay, many concurrent validations of one catreplay 1 token accept it exactly once. Run with -race.
func TestCatreplayConcurrentUseAcceptsOnce(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}
	v := validator()
	v.Replay = func(cti []byte) bool {
		mu.Lock()
		defer mu.Unlock()
		was := seen[string(cti)]
		seen[string(cti)] = true
		return was
	}
	token := claimsToken(t, map[any]any{7: []byte{1}, 308: 1})
	const n = 64
	var wg sync.WaitGroup
	var accepted sync.Map
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Validate(token); err == nil {
				accepted.Store(i, true)
			}
		}()
	}
	wg.Wait()
	count := 0
	accepted.Range(func(any, any) bool { count++; return true })
	if count != 1 {
		t.Fatalf("%d of %d concurrent validations accepted the token, want exactly 1", count, n)
	}
}
