package cat

import (
	"strings"
	"testing"
)

// isFieldName, checked for every byte against RFC 9110's tchar set written out in full.
func TestIsFieldName(t *testing.T) {
	const tchar = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~"
	for i := 0; i < 256; i++ {
		c := byte(i)
		if got, want := isFieldName(string([]byte{c})), strings.IndexByte(tchar, c) >= 0; got != want {
			t.Errorf("isFieldName(%q) = %v, want %v", c, got, want)
		}
	}
	if isFieldName("") {
		t.Error("an empty name was accepted")
	}
}

// mapEntries must read the longer head forms too: 24 or more entries take an extra byte.
func TestMapEntriesWithManyEntries(t *testing.T) {
	m := map[int64]any{}
	for i := int64(0); i < 30; i++ {
		m[i] = i
	}
	entries, ok := mapEntries(enc(t, m))
	if !ok || len(entries) != 30 {
		t.Fatalf("mapEntries: %d entries, ok %v; want 30", len(entries), ok)
	}
	if _, ok := mapEntries(mustHex(t, "b81e")); ok {
		t.Error("a map head promising 30 entries with none present was accepted")
	}
}
