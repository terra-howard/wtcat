package cwt_test

import (
	"fmt"
	"testing"

	"github.com/terra-howard/wtcat/cwt"
)

// Algorithms print as RFC 9053 names them, and still format as their identifiers with %d.
func TestAlgorithmString(t *testing.T) {
	cases := []struct {
		alg        cwt.Algorithm
		name, code string
	}{
		{cwt.HMAC256x64, "HMAC 256/64", "4"},
		{cwt.HMAC256x256, "HMAC 256/256", "5"},
		{cwt.ES256, "ES256", "-7"},
		{cwt.PS256, "PS256", "-37"},
		{cwt.Algorithm(-8), "algorithm -8", "-8"},
	}
	for _, tc := range cases {
		if got := tc.alg.String(); got != tc.name {
			t.Errorf("String() = %q, want %q", got, tc.name)
		}
		if got := fmt.Sprintf("%d", tc.alg); got != tc.code {
			t.Errorf("%%d of %s = %q, want %q", tc.name, got, tc.code)
		}
	}
}
