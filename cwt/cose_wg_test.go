package cwt

// Tests against the COSE working group's examples (decision 0009). They call the internal COSE layer because the
// examples' payloads are plain text, not CWT claims sets.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type coseWGVector struct {
	Title string `json:"title"`
	Input struct {
		Plaintext string `json:"plaintext"`
		Mac0      struct {
			Recipients []struct {
				Key struct {
					K string `json:"k"`
				} `json:"key"`
			} `json:"recipients"`
		} `json:"mac0"`
	} `json:"input"`
	Intermediates struct {
		ToMacHex string `json:"ToMac_hex"`
	} `json:"intermediates"`
	Output struct {
		CBOR string `json:"cbor"`
	} `json:"output"`
}

func loadCOSEWG(t *testing.T, name string) coseWGVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "cose-wg", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	var v coseWGVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

func mustHexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func macKey(t *testing.T, v coseWGVector) []byte {
	t.Helper()
	if len(v.Input.Mac0.Recipients) == 0 {
		t.Fatal("vector has no recipient key")
	}
	k, err := base64.RawURLEncoding.DecodeString(v.Input.Mac0.Recipients[0].Key.K)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestMacStructureMatchesCOSEWG(t *testing.T) {
	v := loadCOSEWG(t, "mac0-tests/HMac-01.json")
	msg, err := parseCOSE(mustHexT(t, v.Output.CBOR), tagMac0)
	if err != nil {
		t.Fatalf("parseCOSE: %v", err)
	}
	got, err := macStructure(msg.protectedRaw, msg.payload)
	if err != nil {
		t.Fatalf("macStructure: %v", err)
	}
	if want := mustHexT(t, v.Intermediates.ToMacHex); !bytes.Equal(got, want) {
		t.Fatalf("MAC structure\n got %x\nwant %x", got, want)
	}
}

func TestVerifyMac0PayloadCOSEWGHMAC256(t *testing.T) {
	v := loadCOSEWG(t, "mac0-tests/HMac-01.json")
	payload, err := verifyMac0Payload(mustHexT(t, v.Output.CBOR), macKey(t, v))
	if err != nil {
		t.Fatalf("verifyMac0Payload: %v", err)
	}
	if string(payload) != v.Input.Plaintext {
		t.Fatalf("payload = %q, want %q", payload, v.Input.Plaintext)
	}
}

func TestCOSEWGMac0Rejections(t *testing.T) {
	cases := []struct {
		file string
		want error
		why  string
	}{
		{"mac0-tests/mac-fail-01.json", ErrMalformed, "COSE tag changed to 992"},
		{"mac0-tests/mac-fail-02.json", ErrVerification, "MAC tag changed"},
		{"mac0-tests/mac-fail-03.json", ErrUnsupported, "alg changed to -999"},
		{"mac0-tests/mac-fail-04.json", ErrUnsupported, "alg changed to the text string Unknown"},
		{"mac0-tests/mac-fail-06.json", ErrUnsupported, "content type added to the protected header; decision 0008 rule 2 refuses unknown labels"},
		{"mac0-tests/mac-fail-07.json", ErrVerification, "content type removed from the protected header after MACing"},
		// The working group expects this one to pass. Decision 0009 item 4 explains the deliberate divergence:
		// alg in the unprotected header allows relabelling HMAC 256/256 as HMAC 256/64.
		{"mac0-tests/mac-pass-01.json", ErrMalformed, "alg only in the unprotected header"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			v := loadCOSEWG(t, tc.file)
			_, err := verifyMac0Payload(mustHexT(t, v.Output.CBOR), macKey(t, v))
			if !errors.Is(err, tc.want) {
				t.Fatalf("%s (%s): got %v, want an error wrapping %v", v.Title, tc.why, err, tc.want)
			}
		})
	}
}
