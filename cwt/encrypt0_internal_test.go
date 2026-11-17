package cwt

// COSE_Encrypt0 against the COSE working group's examples (decision 0030), from testdata/cose-wg, pinned as
// decision 0009 records.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func loadEncrypt0(t *testing.T, path string) (token []byte, lookup KeyLookup) {
	t.Helper()
	raw, err := os.ReadFile("testdata/cose-wg/" + path)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Input struct {
			Encrypted struct {
				Protected   map[string]any `json:"protected"`
				Unprotected map[string]any `json:"unprotected"`
				Recipients  []struct {
					Key vectorKey `json:"key"`
				} `json:"recipients"`
			} `json:"encrypted"`
		} `json:"input"`
		Output struct {
			CBOR string `json:"cbor"`
		} `json:"output"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	alg := map[string]Algorithm{"A128GCM": A128GCM, "A192GCM": A192GCM, "A256GCM": A256GCM}
	name, _ := v.Input.Encrypted.Protected["alg"].(string)
	if name == "" {
		name, _ = v.Input.Encrypted.Unprotected["alg"].(string)
	}
	key := Key{Algorithm: alg[name], Material: b64(t, v.Input.Encrypted.Recipients[0].Key.K)}
	return mustHexT(t, v.Output.CBOR), func(kid []byte) (Key, error) { return key, nil }
}

// TestDecryptMessageVectors runs the working group's COSE_Encrypt0 vectors through DecryptMessage. A nil want means
// it must decrypt to "This is the content.". Three vectors the working group marks as passing are refused here on
// purpose: enc-pass-01 and enc-pass-03 carry alg in the unprotected header (decision 0009), and enc-pass-02 needs
// external data, which this package never supplies.
func TestDecryptMessageVectors(t *testing.T) {
	cases := []struct {
		path string
		want error
	}{
		{"aes-gcm-examples/aes-gcm-enc-01.json", nil},
		{"aes-gcm-examples/aes-gcm-enc-02.json", nil},
		{"aes-gcm-examples/aes-gcm-enc-03.json", nil},
		{"encrypted-tests/aes-gcm-01.json", nil},

		{"encrypted-tests/enc-pass-01.json", ErrMalformed},
		{"encrypted-tests/enc-pass-02.json", ErrVerification},
		{"encrypted-tests/enc-pass-03.json", ErrMalformed},

		{"aes-gcm-examples/aes-gcm-enc-04.json", ErrVerification},
		{"encrypted-tests/enc-fail-01.json", ErrMalformed},
		{"encrypted-tests/enc-fail-02.json", ErrVerification},
		{"encrypted-tests/enc-fail-03.json", ErrUnsupported},
		{"encrypted-tests/enc-fail-04.json", ErrUnsupported},
		{"encrypted-tests/enc-fail-06.json", ErrUnsupported},
		{"encrypted-tests/enc-fail-07.json", ErrVerification},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			token, lookup := loadEncrypt0(t, tc.path)
			msg, err := DecryptMessage(token, lookup)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("DecryptMessage: %v", err)
				}
				if !bytes.Equal(msg.Payload, []byte("This is the content.")) {
					t.Fatalf("plaintext %q", msg.Payload)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want an error wrapping %v", err, tc.want)
			}
		})
	}
}

// TestDecryptMessageKeys checks that the key decides the algorithm, as for verification (decision 0015).
func TestDecryptMessageKeys(t *testing.T) {
	token, lookup := loadEncrypt0(t, "aes-gcm-examples/aes-gcm-enc-01.json")
	right, _ := lookup(nil)
	for name, tc := range map[string]struct {
		key  Key
		want error
	}{
		"a key for another AES-GCM size":   {Key{Algorithm: A256GCM, Material: right.Material}, ErrVerification},
		"a MAC key":                        {Key{Algorithm: HMAC256x256, Material: right.Material}, ErrVerification},
		"key material of the wrong length": {Key{Algorithm: A128GCM, Material: []byte("short")}, ErrVerification},
		"key material of the wrong type":   {Key{Algorithm: A128GCM, Material: "not bytes"}, ErrVerification},
		"the right key":                    {right, nil},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecryptMessage(token, func([]byte) (Key, error) { return tc.key, nil })
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
