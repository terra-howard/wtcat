package cwt

// COSE_Sign1 and PS256 tests against the COSE working group's examples (decision 0009). The PS256 vector is a
// multi-signer COSE_Sign, so it checks the PS256 primitive over its ToBeSign bytes; RFC 8392 A.3 and the Sign1
// vectors check the COSE_Sign1 envelope.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
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

type pssVector struct {
	Input struct {
		Sign struct {
			Signers []struct {
				Key struct {
					N string `json:"n_hex"`
					E string `json:"e_hex"`
				} `json:"key"`
			} `json:"signers"`
		} `json:"sign"`
	} `json:"input"`
	Intermediates struct {
		Signers []struct {
			ToBeSignHex string `json:"ToBeSign_hex"`
		} `json:"signers"`
	} `json:"intermediates"`
	Output struct {
		CBOR string `json:"cbor"`
	} `json:"output"`
}

// loadPSS returns the vector's public key, the bytes it signed, and its signature.
func loadPSS(t *testing.T) (*rsa.PublicKey, []byte, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "cose-wg", "rsa-pss-examples", "rsa-pss-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v pssVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	n, err := hex.DecodeString(v.Input.Sign.Signers[0].Key.N)
	if err != nil {
		t.Fatal(err)
	}
	e, err := hex.DecodeString(v.Input.Sign.Signers[0].Key.E)
	if err != nil {
		t.Fatal(err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}

	// COSE_Sign: 98([protected, unprotected, payload, [[signer protected, signer unprotected, signature]]])
	var tag cbor.Tag
	if err := cbor.Unmarshal(mustHexT(t, v.Output.CBOR), &tag); err != nil {
		t.Fatal(err)
	}
	body, ok := tag.Content.([]any)
	if tag.Number != 98 || !ok || len(body) != 4 {
		t.Fatalf("unexpected COSE_Sign shape: tag %d", tag.Number)
	}
	signers, ok := body[3].([]any)
	if !ok || len(signers) != 1 {
		t.Fatal("unexpected signers shape")
	}
	signer, ok := signers[0].([]any)
	if !ok || len(signer) != 3 {
		t.Fatal("unexpected signer shape")
	}
	sig, ok := signer[2].([]byte)
	if !ok {
		t.Fatal("signature is not a byte string")
	}
	return pub, mustHexT(t, v.Intermediates.Signers[0].ToBeSignHex), sig
}

func TestPS256MatchesCOSEWG(t *testing.T) {
	pub, toBeSigned, sig := loadPSS(t)
	if err := verifyPS256(pub, toBeSigned, sig); err != nil {
		t.Fatalf("verifyPS256: %v", err)
	}
}

// TestPS256RejectsKeysBelow2048Bits uses a signature that is valid for its own 1024-bit key, so only the size
// rule can reject it. (A first version reused the vector's signature, which fails on any other key regardless;
// hand mutation testing showed the size rule could be weakened without that test noticing.)
func TestPS256RejectsKeysBelow2048Bits(t *testing.T) {
	small, err := testRSAKey(t, 1024)
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned := []byte("any bytes")
	digest := sha256.Sum256(toBeSigned)
	sig, err := rsa.SignPSS(rand.Reader, small, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPS256(&small.PublicKey, toBeSigned, sig); !errors.Is(err, ErrVerification) {
		t.Fatalf("got %v, want ErrVerification for a 1024-bit key", err)
	}
}

func TestPS256Rejects(t *testing.T) {
	pub, toBeSigned, sig := loadPSS(t)
	changed := append([]byte{}, sig...)
	changed[len(changed)-1] ^= 0x01
	cases := []struct {
		name string
		key  any
		sig  []byte
	}{
		{"signature changed", pub, changed},
		{"ECDSA-shaped key", []byte("not an RSA key"), sig},
		{"nil key", nil, sig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyPS256(tc.key, toBeSigned, tc.sig); !errors.Is(err, ErrVerification) {
				t.Fatalf("got %v, want an error wrapping ErrVerification", err)
			}
		})
	}
}
