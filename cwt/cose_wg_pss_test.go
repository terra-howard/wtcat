package cwt

// PS256 checked against the COSE working group's rsa-pss-01 vector (decision 0009, item 5). The vector is a
// multi-signer COSE_Sign, so it checks the PS256 primitive over its ToBeSign bytes; RFC 8392 A.3 and the Sign1
// vectors check the COSE_Sign1 envelope.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

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

func TestPS256Rejects(t *testing.T) {
	pub, toBeSigned, sig := loadPSS(t)
	changed := append([]byte{}, sig...)
	changed[len(changed)-1] ^= 0x01
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		key  any
		sig  []byte
	}{
		{"signature changed", pub, changed},
		{"ECDSA-shaped key", []byte("not an RSA key"), sig},
		{"nil key", nil, sig},
		{"1024-bit key, below RFC 8230's 2048-bit floor", &small.PublicKey, sig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyPS256(tc.key, toBeSigned, tc.sig); !errors.Is(err, ErrVerification) {
				t.Fatalf("got %v, want an error wrapping ErrVerification", err)
			}
		})
	}
}
