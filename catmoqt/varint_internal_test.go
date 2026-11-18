package catmoqt

import (
	"encoding/hex"
	"testing"
)

// TestReadVarint checks draft-ietf-moq-transport-22's variable-length integers against the draft's own examples
// (section "Variable-Length Integers"), including the longer encodings it allows for the same value.
func TestReadVarint(t *testing.T) {
	for _, tc := range []struct {
		hex  string
		want uint64
	}{
		{"25", 37},
		{"8025", 37},
		{"bbbd", 15293},
		{"ed7f3e7d", 226442877},
		{"faa1a0e403d8", 2893212287960},
		{"fc8998abc66bc0", 151288809941952},
		{"fefa318fa8e3ca11", 70423237261249041},
		{"ffffffffffffffffff", 18446744073709551615},
		{"00", 0},
		{"8000", 0},
		{"c00000", 0},
	} {
		b, err := hex.DecodeString(tc.hex + "aa") // a trailing byte, which must be left unread
		if err != nil {
			t.Fatal(err)
		}
		got, rest, err := readVarint(b)
		if err != nil || got != tc.want || len(rest) != 1 || rest[0] != 0xaa {
			t.Errorf("%s: got %d, rest %x, %v; want %d", tc.hex, got, rest, err, tc.want)
		}
	}
	for _, short := range []string{"", "80", "c000", "fefa318fa8e3ca", "ffffffffffffffff"} {
		b, _ := hex.DecodeString(short)
		if _, _, err := readVarint(b); err == nil {
			t.Errorf("%q: a truncated integer was accepted", short)
		}
	}
}
