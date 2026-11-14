package cwt

// Helpers shared by the internal tests that read the COSE working group's vectors in testdata/cose-wg
// (decision 0009).

import (
	"encoding/hex"
	"testing"
)

func mustHexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
