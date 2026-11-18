package cat

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/hex"
	"testing"
)

// TestCOSEKeyThumbprints checks both thumbprints of a proof's key against values computed elsewhere (task 76): RFC
// 9679 section 6's COSE Key Thumbprint of an EC2 P-256 key, RFC 8037 appendix A.3's JWK Thumbprint of an Ed25519
// key, and, where no published example exists, values computed in Python from the key bytes, independently of this
// package: the COSE Key Thumbprint of that Ed25519 key, and both thumbprints of a P-384 key OpenSSL generated.
func TestCOSEKeyThumbprints(t *testing.T) {
	h := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	curve := func(kty, crv int64) proofCurve {
		for _, c := range proofCurves {
			if c.kty == kty && c.crv == crv {
				return c
			}
		}
		t.Fatalf("no curve %d/%d", kty, crv)
		return proofCurve{}
	}
	ec := func(ec elliptic.Curve, crv int64, x, y string) proofKey {
		pub, err := ecdsa.ParseUncompressedPublicKey(ec, append(append([]byte{4}, h(x)...), h(y)...))
		if err != nil {
			t.Fatal(err)
		}
		return proofKey{pub: pub, curve: curve(2, crv), x: h(x), y: h(y)}
	}
	edX := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	cases := []struct {
		name     string
		key      proofKey
		ckt, jkt string // empty when no value from elsewhere is known
	}{
		{"RFC 9679 section 6, P-256", ec(elliptic.P256(), 1,
			"65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d",
			"1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"),
			"496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec", ""},
		{"RFC 8037 appendix A, Ed25519", proofKey{pub: ed25519.PublicKey(h(edX)), curve: curve(1, 6), x: h(edX)},
			"866eefbd6718c8846cd7ddfe43fc74ab1daac4538ff8514ea2ec2d410a415743",
			"90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89"},
		{"a P-384 key", ec(elliptic.P384(), 2,
			"57e01e5ec1a819d985c8dbe9ea24838d5bba8c3ad5685b2452de6b65221e847c26250e4e9bf981fbce9122b75879326d",
			"d26a27fc78f4e11eee35eb7554615b5c9725dbbaaff28bd11eff344f00124e77d669e3a17020661a6a707c992946a220"),
			"a6835a6ed59fdb457393bad6a461f06bc68adf93fe69e9f4dcfb01acdd06ec7c",
			"c03bdc6ec1244d05012df7ea104dd8cb632867d47a7605086392dd6bae3b890f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ckt, jkt, err := coseThumbprints(tc.key)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(ckt); got != tc.ckt {
				t.Errorf("ckt = %s, want %s", got, tc.ckt)
			}
			if got := hex.EncodeToString(jkt); tc.jkt != "" && got != tc.jkt {
				t.Errorf("jkt = %s, want %s", got, tc.jkt)
			}
		})
	}
}
