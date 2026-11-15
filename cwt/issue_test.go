package cwt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/terra-howard/wtcat/cwt"
)

func TestIssueVerifies(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	payload := encode(t, map[int64]any{1: "issuer", 4: 1700000000})
	for _, tc := range []struct {
		name   string
		sign   cwt.SigningKey
		verify cwt.Key
	}{
		{"HMAC 256/256", cwt.SigningKey{Algorithm: cwt.HMAC256x256, KID: []byte("m1"), Material: testKey}, cwt.Key{Algorithm: cwt.HMAC256x256, Material: testKey}},
		{"ES256", cwt.SigningKey{Algorithm: cwt.ES256, KID: []byte("e1"), Material: ec}, cwt.Key{Algorithm: cwt.ES256, Material: &ec.PublicKey}},
		{"PS256", cwt.SigningKey{Algorithm: cwt.PS256, Material: rk}, cwt.Key{Algorithm: cwt.PS256, Material: &rk.PublicKey}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := cwt.Issue(payload, tc.sign)
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			msg, err := cwt.VerifyMessage(token, func(kid []byte) (cwt.Key, error) {
				if !bytes.Equal(kid, tc.sign.KID) {
					t.Errorf("kid = %q, want %q", kid, tc.sign.KID)
				}
				return tc.verify, nil
			})
			if err != nil {
				t.Fatalf("VerifyMessage: %v", err)
			}
			if !bytes.Equal(msg.Payload, payload) || msg.Algorithm != tc.sign.Algorithm {
				t.Errorf("message = %+v", msg)
			}
			// The protected header holds alg alone, and the tag matches the algorithm.
			want := byte(0xd2)
			if tc.sign.Algorithm == cwt.HMAC256x256 {
				want = 0xd1
			}
			if token[0] != want {
				t.Errorf("first byte %#x, want COSE tag byte %#x", token[0], want)
			}
		})
	}
}

func TestIssueRefuses(t *testing.T) {
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]cwt.SigningKey{
		"an unsupported algorithm":     {Algorithm: 999, Material: testKey},
		"HMAC 256/64, not for issuing": {Algorithm: cwt.HMAC256x64, Material: testKey},
		"an empty HMAC secret":         {Algorithm: cwt.HMAC256x256, Material: []byte{}},
		"an EC key for HMAC":           {Algorithm: cwt.HMAC256x256, Material: ec},
		"a P-384 key for ES256":        {Algorithm: cwt.ES256, Material: ec384},
		"a public key for ES256":       {Algorithm: cwt.ES256, Material: &ec.PublicKey},
		"an RSA key below 2048 bits":   {Algorithm: cwt.PS256, Material: small},
		"a nil RSA key":                {Algorithm: cwt.PS256, Material: (*rsa.PrivateKey)(nil)},
	} {
		if _, err := cwt.Issue([]byte{0xa0}, key); err == nil {
			t.Errorf("%s: Issue succeeded", name)
		}
	}
}
