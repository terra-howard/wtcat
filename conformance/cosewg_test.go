package conformance

// Protected tests from the COSE working group's examples (https://github.com/cose-wg/Examples), at the commit
// cwt/testdata/cose-wg/SOURCE.md records (decision 0009), for messages with several signers or recipients
// (decision 0029) and for COSE_Encrypt0 (decision 0030).
//
// Only the vectors on which this project agrees with the working group are here: those it marks as passing that
// verify or decrypt, and those it marks as failing, which must be refused. The vectors the working group marks as
// passing and this project refuses on purpose stay in the ordinary tests, since those refusals are this project's
// own decisions. A failing vector is checked only for being refused, not for which error kind, which is also this
// project's classification. Each vector file's SHA-256 is pinned below, so that editing a vector fails these tests
// as surely as editing this file fails the census. The hashes were written in by script from the files themselves.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/terra-howard/wtcat/cwt"
)

const wgDir = "../cwt/testdata/cose-wg/"

var wgHashes = map[string]string{
	"RFC8152/Appendix_C_1_1.json":          "b0ae2e0119b9945b9ff1296a4a076fb5e2b1e2ff9771242662821cfeb1fa669b",
	"RFC8152/Appendix_C_1_2.json":          "fe022100401c82d1219ebe59cddeb277ac058316d229f31e2250fd89eb98e28c",
	"mac-tests/HMac-01.json":               "8fe6f2ed871e964ebe2847a2265ee56a6c40a5df66fee162275db7186e638563",
	"hmac-examples/HMac-05.json":           "4841f5e9949225039d404a35f67d1a0001f712ccb328829c02f44312783f486d",
	"sign-tests/sign-fail-01.json":         "63e707929b20dfb069bcd1c6af9032a0eea621c87f299c6ebb3d463862164e72",
	"sign-tests/sign-fail-02.json":         "92cde489ecfc03ec467ef6a965d56ed81d64994cb318bea810945f4b0f01549b",
	"sign-tests/sign-fail-03.json":         "b66d6529da67145112021600105ba0d38e83fa681c03224980636dc5293c4af6",
	"sign-tests/sign-fail-04.json":         "42e1a99727db48224baf88fde8d5e59bd736b78ecb9a9c4706ccbee5639f70ae",
	"sign-tests/sign-fail-06.json":         "adba4c0982705c3c1c8a65d5db4b15c34e4f16d836e29b17ef5fbd08059e84b2",
	"sign-tests/sign-fail-07.json":         "c7b452030bd2052891a3b1169e9faa99d0a6402773e4868c21e27464deacb8eb",
	"mac-tests/mac-fail-01.json":           "6ebf7926d92e5da4608e942cad330d843c1226a5582e5ff7c3db95944e8b8b1c",
	"mac-tests/mac-fail-02.json":           "f5a3ed4a808c49f1a58fc2528738c4de6344d018f90de65afc0ca660293725e2",
	"mac-tests/mac-fail-03.json":           "ce57fd7345a6949afdb1e81957895a4b3706f6913cd39a4764fb4ceeeeb89673",
	"mac-tests/mac-fail-04.json":           "00f1c99b73320a459144e00e8743be905083e4ef699baa3a3f89c5a2b108358e",
	"mac-tests/mac-fail-06.json":           "dab8aa79dac87ad66ee62665eccd9af4f6cc5c91bc69c4b7769e2804c5000011",
	"mac-tests/mac-fail-07.json":           "99ce9765006ad22782ec98b9a4da8ba42295d06538d2cef5bfa68aea70d03126",
	"aes-gcm-examples/aes-gcm-enc-01.json": "e25e050b47ab0e0f8a207a47e717a4c7046a19d13c8ebe111ccd66bfcf12a224",
	"aes-gcm-examples/aes-gcm-enc-02.json": "fede565db68d57d7f55264b27ad12e7bdf7ceb999bc729e66c9d5ed914fa23c1",
	"aes-gcm-examples/aes-gcm-enc-03.json": "a44edfceac918123d4fea8f8e774907344ff8c916564fcef1a1460bfaba12d8c",
	"encrypted-tests/aes-gcm-01.json":      "b0df6739f885e3240b5efc4a62c31de3ad360084e614e43701050c1e7606967d",
	"encrypted-tests/enc-fail-01.json":     "04be8a8b3662e41807ab10f5fe39a6df5abb4dff327d2804c509acd409698a3f",
	"encrypted-tests/enc-fail-02.json":     "7573307d6dbd850c66b26f2a2811f2c38d5001e5a96c1e8cb3030a3fa658e361",
	"encrypted-tests/enc-fail-03.json":     "30bbfe7d5899c6a829ed2e804b3032886e9c317b618c02dba7f017dca0679ac5",
	"encrypted-tests/enc-fail-04.json":     "bc8aa5274d941e3e10f420bb55c6a8475dee3ac98d1ceea1dae7b017eebef655",
	"encrypted-tests/enc-fail-06.json":     "190ec685351e3b4de5e306c4115ac989680fba52d72e747ce3f08b71b2c4ca43",
	"encrypted-tests/enc-fail-07.json":     "9cc74312d5c3e668e0fd530432924402a105ef5d30affda2ac1ac4b04260e169",
}

type wgKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	K   string `json:"k"`
}

type wgVector struct {
	Input struct {
		Sign *struct {
			Signers []struct {
				Key wgKey `json:"key"`
			} `json:"signers"`
		} `json:"sign"`
		Mac *struct {
			Recipients []struct {
				Key wgKey `json:"key"`
			} `json:"recipients"`
		} `json:"mac"`
		Encrypted *struct {
			Protected   map[string]any `json:"protected"`
			Unprotected map[string]any `json:"unprotected"`
			Recipients  []struct {
				Key wgKey `json:"key"`
			} `json:"recipients"`
		} `json:"encrypted"`
	} `json:"input"`
	Output struct {
		CBOR string `json:"cbor"`
	} `json:"output"`
}

// loadWG reads a vector, after checking the file is the one pinned.
func loadWG(t *testing.T, path string) (message []byte, v wgVector) {
	t.Helper()
	want, ok := wgHashes[path]
	if !ok {
		t.Fatalf("%s has no pinned hash", path)
	}
	raw, err := os.ReadFile(wgDir + path)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != want {
		t.Fatalf("%s has changed: its SHA-256 is %x, pinned %s", path, sum, want)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	message, err = hex.DecodeString(v.Output.CBOR)
	if err != nil {
		t.Fatal(err)
	}
	return message, v
}

func wgBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// wgLookup finds a vector's ES256 and symmetric keys by kid, giving symmetric keys the MAC algorithm macAlg.
func wgLookup(t *testing.T, v wgVector, macAlg cwt.Algorithm) cwt.KeyLookup {
	t.Helper()
	keys := map[string]cwt.Key{}
	var all []wgKey
	if v.Input.Sign != nil {
		for _, s := range v.Input.Sign.Signers {
			all = append(all, s.Key)
		}
	}
	if v.Input.Mac != nil {
		for _, r := range v.Input.Mac.Recipients {
			all = append(all, r.Key)
		}
	}
	for _, k := range all {
		switch {
		case k.Kty == "EC" && k.Crv == "P-256":
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, wgBytes(t, k.X)...), wgBytes(t, k.Y)...))
			if err != nil {
				t.Fatal(err)
			}
			keys[k.Kid] = cwt.Key{Algorithm: cwt.ES256, Material: pub}
		case k.Kty == "oct":
			keys[k.Kid] = cwt.Key{Algorithm: macAlg, Material: wgBytes(t, k.K)}
		}
	}
	return func(kid []byte) (cwt.Key, error) {
		if k, ok := keys[string(kid)]; ok {
			return k, nil
		}
		return cwt.Key{}, errors.New("unknown kid")
	}
}

// wgEncryptLookup gives a COSE_Encrypt0 vector's key the AES-GCM algorithm its header names.
func wgEncryptLookup(t *testing.T, v wgVector) cwt.KeyLookup {
	t.Helper()
	e := v.Input.Encrypted
	name, _ := e.Protected["alg"].(string)
	if name == "" {
		name, _ = e.Unprotected["alg"].(string)
	}
	alg := map[string]cwt.Algorithm{"A128GCM": cwt.A128GCM, "A192GCM": cwt.A192GCM, "A256GCM": cwt.A256GCM}[name]
	key := cwt.Key{Algorithm: alg, Material: wgBytes(t, e.Recipients[0].Key.K)}
	return func([]byte) (cwt.Key, error) { return key, nil }
}

var wgContent = []byte("This is the content.")

// TestCOSEWGSeveralSignersOrRecipients checks that COSE_Sign and COSE_Mac messages the working group marks as
// passing verify, with the content as payload. RFC 8152 C.1.2's P-521 signer is unknown here, so it is skipped and
// the ES256 signer verifies.
func TestCOSEWGSeveralSignersOrRecipients(t *testing.T) {
	for _, tc := range []struct {
		path   string
		macAlg cwt.Algorithm
	}{
		{"RFC8152/Appendix_C_1_1.json", 0},
		{"RFC8152/Appendix_C_1_2.json", 0},
		{"mac-tests/HMac-01.json", cwt.HMAC256x256},
		{"hmac-examples/HMac-05.json", cwt.HMAC256x64},
	} {
		t.Run(tc.path, func(t *testing.T) {
			message, v := loadWG(t, tc.path)
			msg, err := cwt.VerifyMessage(message, wgLookup(t, v, tc.macAlg))
			if err != nil {
				t.Fatalf("VerifyMessage: %v", err)
			}
			if !bytes.Equal(msg.Payload, wgContent) {
				t.Fatalf("payload %q", msg.Payload)
			}
		})
	}
}

// TestCOSEWGSeveralSignersOrRecipientsRefused checks that every COSE_Sign and COSE_Mac message the working group
// marks as failing is refused.
func TestCOSEWGSeveralSignersOrRecipientsRefused(t *testing.T) {
	for _, tc := range []struct {
		path   string
		macAlg cwt.Algorithm
	}{
		{"sign-tests/sign-fail-01.json", 0},
		{"sign-tests/sign-fail-02.json", 0},
		{"sign-tests/sign-fail-03.json", 0},
		{"sign-tests/sign-fail-04.json", 0},
		{"sign-tests/sign-fail-06.json", 0},
		{"sign-tests/sign-fail-07.json", 0},
		{"mac-tests/mac-fail-01.json", cwt.HMAC256x256},
		{"mac-tests/mac-fail-02.json", cwt.HMAC256x256},
		{"mac-tests/mac-fail-03.json", cwt.HMAC256x256},
		{"mac-tests/mac-fail-04.json", cwt.HMAC256x256},
		{"mac-tests/mac-fail-06.json", cwt.HMAC256x256},
		{"mac-tests/mac-fail-07.json", cwt.HMAC256x256},
	} {
		t.Run(tc.path, func(t *testing.T) {
			message, v := loadWG(t, tc.path)
			if msg, err := cwt.VerifyMessage(message, wgLookup(t, v, tc.macAlg)); err == nil {
				t.Fatalf("a failing vector verified, payload %q", msg.Payload)
			}
		})
	}
}

// TestCOSEWGEncrypt0 checks that COSE_Encrypt0 messages the working group marks as passing decrypt to the content.
func TestCOSEWGEncrypt0(t *testing.T) {
	for _, path := range []string{
		"aes-gcm-examples/aes-gcm-enc-01.json",
		"aes-gcm-examples/aes-gcm-enc-02.json",
		"aes-gcm-examples/aes-gcm-enc-03.json",
		"encrypted-tests/aes-gcm-01.json",
	} {
		t.Run(path, func(t *testing.T) {
			message, v := loadWG(t, path)
			msg, err := cwt.DecryptMessage(message, wgEncryptLookup(t, v))
			if err != nil {
				t.Fatalf("DecryptMessage: %v", err)
			}
			if !bytes.Equal(msg.Payload, wgContent) {
				t.Fatalf("plaintext %q", msg.Payload)
			}
		})
	}
}

// TestCOSEWGEncrypt0Refused checks that every COSE_Encrypt0 message the working group marks as failing is refused.
func TestCOSEWGEncrypt0Refused(t *testing.T) {
	for _, path := range []string{
		"encrypted-tests/enc-fail-01.json",
		"encrypted-tests/enc-fail-02.json",
		"encrypted-tests/enc-fail-03.json",
		"encrypted-tests/enc-fail-04.json",
		"encrypted-tests/enc-fail-06.json",
		"encrypted-tests/enc-fail-07.json",
	} {
		t.Run(path, func(t *testing.T) {
			message, v := loadWG(t, path)
			if msg, err := cwt.DecryptMessage(message, wgEncryptLookup(t, v)); err == nil {
				t.Fatalf("a failing vector decrypted, plaintext %q", msg.Payload)
			}
		})
	}
}
