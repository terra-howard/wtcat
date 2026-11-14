package cwt

// COSE_Sign1 tests against the COSE working group's examples (decision 0009, extended in task 3).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type coseWGSign1Vector struct {
	Title string `json:"title"`
	Input struct {
		Plaintext string `json:"plaintext"`
		Sign0     struct {
			Key struct {
				Crv string `json:"crv"`
				X   string `json:"x"`
				Y   string `json:"y"`
			} `json:"key"`
		} `json:"sign0"`
	} `json:"input"`
	Intermediates struct {
		ToBeSignHex string `json:"ToBeSign_hex"`
	} `json:"intermediates"`
	Output struct {
		CBOR string `json:"cbor"`
	} `json:"output"`
}

func loadSign1(t *testing.T, name string) coseWGSign1Vector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "cose-wg", "sign1-tests", name))
	if err != nil {
		t.Fatal(err)
	}
	var v coseWGSign1Vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

func p256Key(t *testing.T, v coseWGSign1Vector) *ecdsa.PublicKey {
	t.Helper()
	if v.Input.Sign0.Key.Crv != "P-256" {
		t.Fatalf("vector key curve %q, want P-256", v.Input.Sign0.Key.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(v.Input.Sign0.Key.X)
	if err != nil {
		t.Fatal(err)
	}
	y, err := base64.RawURLEncoding.DecodeString(v.Input.Sign0.Key.Y)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{0x04}, x...), y...))
	if err != nil {
		t.Fatalf("vector key does not parse: %v", err)
	}
	return pub
}

func TestSigStructureMatchesCOSEWG(t *testing.T) {
	v := loadSign1(t, "sign-pass-03.json")
	msg, err := parseCOSE(mustHexT(t, v.Output.CBOR), tagSign1)
	if err != nil {
		t.Fatalf("parseCOSE: %v", err)
	}
	got, err := sigStructure(msg.protectedRaw, msg.payload)
	if err != nil {
		t.Fatalf("sigStructure: %v", err)
	}
	if want := mustHexT(t, v.Intermediates.ToBeSignHex); !bytes.Equal(got, want) {
		t.Fatalf("Sig_structure\n got %x\nwant %x", got, want)
	}
}

func TestVerifySign1PayloadCOSEWGUntagged(t *testing.T) {
	v := loadSign1(t, "sign-pass-03.json")
	payload, err := verifySign1Payload(mustHexT(t, v.Output.CBOR), p256Key(t, v))
	if err != nil {
		t.Fatalf("verifySign1Payload: %v", err)
	}
	if string(payload) != v.Input.Plaintext {
		t.Fatalf("payload = %q, want %q", payload, v.Input.Plaintext)
	}
}

func TestCOSEWGSign1Rejections(t *testing.T) {
	cases := []struct {
		file string
		want error
	}{
		{"sign-fail-01.json", ErrMalformed},    // COSE tag changed to 998
		{"sign-fail-02.json", ErrVerification}, // signature changed
		{"sign-fail-03.json", ErrUnsupported},  // alg changed to -999
		{"sign-fail-04.json", ErrUnsupported},  // alg changed to a text string
		{"sign-fail-06.json", ErrUnsupported},  // content type added to the protected header
		{"sign-fail-07.json", ErrVerification}, // content type removed from the protected header after signing
		// Expected to pass by the working group; refused here, see decision 0009 item 4.
		{"sign-pass-01.json", ErrMalformed}, // alg only in the unprotected header
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			v := loadSign1(t, tc.file)
			_, err := verifySign1Payload(mustHexT(t, v.Output.CBOR), p256Key(t, v))
			if !errors.Is(err, tc.want) {
				t.Fatalf("%s: got %v, want an error wrapping %v", v.Title, err, tc.want)
			}
		})
	}
}
