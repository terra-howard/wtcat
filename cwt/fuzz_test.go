package cwt_test

// Fuzz targets under decision 0011. Each checks that no input panics and that every error is classified.
// Run one with, for example: go test ./cwt -run=^$ -fuzz=FuzzVerifyMac0 -fuzztime=60s

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/terra-howard/wtcat/cwt"
)

// Seeds from RFC 8392 Appendix A (also used, verbatim, by the protected tests in conformance/).
const (
	seedClaimsA1 = "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71"
	seedSignedA3 = "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30"
	seedMacedA4  = "d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200"
	keyA22       = "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388"
	keyA23Point  = "04143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9"
)

func seed(f *testing.F, hexes ...string) {
	for _, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
}

// checkClassified fails the fuzz run if err is not nil and wraps none of the documented kinds.
func checkClassified(t *testing.T, err error, kinds ...error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, k := range kinds {
		if errors.Is(err, k) {
			return
		}
	}
	t.Fatalf("unclassified error: %v", err)
}

func FuzzDecodeClaims(f *testing.F) {
	seed(f, seedClaimsA1)
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := cwt.DecodeClaims(data)
		checkClassified(t, err, cwt.ErrMalformed, cwt.ErrUnsupported)
		if err == nil && c == nil {
			t.Fatal("nil claims without an error")
		}
	})
}

func FuzzVerifyMac0(f *testing.F) {
	seed(f, seedMacedA4, seedSignedA3, seedClaimsA1)
	key, err := hex.DecodeString(keyA22)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := cwt.VerifyMac0(data, key)
		checkClassified(t, err, cwt.ErrVerification, cwt.ErrMalformed, cwt.ErrUnsupported)
		if err == nil && c == nil {
			t.Fatal("nil claims without an error")
		}
	})
}

func FuzzVerifySign1(f *testing.F) {
	seed(f, seedSignedA3, seedMacedA4, seedClaimsA1)
	point, err := hex.DecodeString(keyA23Point)
	if err != nil {
		f.Fatal(err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := cwt.VerifySign1(data, pub)
		checkClassified(t, err, cwt.ErrVerification, cwt.ErrMalformed, cwt.ErrUnsupported)
		if err == nil && c == nil {
			t.Fatal("nil claims without an error")
		}
	})
}
