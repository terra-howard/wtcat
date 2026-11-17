package cwt

// COSE_Sign and COSE_Mac against the COSE working group's examples (decision 0029), from testdata/cose-wg, pinned
// as decision 0009 records.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

type multiVector struct {
	Input struct {
		Sign *struct {
			Signers []struct {
				Key vectorKey `json:"key"`
			} `json:"signers"`
		} `json:"sign"`
		Mac *struct {
			Recipients []struct {
				Key vectorKey `json:"key"`
			} `json:"recipients"`
		} `json:"mac"`
	} `json:"input"`
	Intermediates struct {
		ToMacHex string `json:"ToMac_hex"`
		Signers  []struct {
			ToBeSignHex string `json:"ToBeSign_hex"`
		} `json:"signers"`
	} `json:"intermediates"`
	Output struct {
		CBOR string `json:"cbor"`
	} `json:"output"`
}

type vectorKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	K   string `json:"k"`
}

func loadMulti(t *testing.T, path string) (token []byte, v multiVector) {
	t.Helper()
	raw, err := os.ReadFile("testdata/cose-wg/" + path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return mustHexT(t, v.Output.CBOR), v
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// lookupFor returns a KeyLookup that knows the vector's P-256 signers as ES256 and its symmetric recipients with
// the given MAC algorithm. Other keys, such as RFC 8152 C.1.2's P-521 signer, are unknown to it.
func lookupFor(t *testing.T, v multiVector, macAlg Algorithm) KeyLookup {
	t.Helper()
	keys := map[string]Key{}
	var all []vectorKey
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
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, b64(t, k.X)...), b64(t, k.Y)...))
			if err != nil {
				t.Fatal(err)
			}
			keys[k.Kid] = Key{Algorithm: ES256, Material: pub}
		case k.Kty == "oct":
			keys[k.Kid] = Key{Algorithm: macAlg, Material: b64(t, k.K)}
		}
	}
	return func(kid []byte) (Key, error) {
		if k, ok := keys[string(kid)]; ok {
			return k, nil
		}
		return Key{}, errors.New("unknown kid")
	}
}

// TestMultiStructuresMatchVectors checks the bytes signed or MACed against each vector's intermediates.
func TestMultiStructuresMatchVectors(t *testing.T) {
	for _, path := range []string{"RFC8152/Appendix_C_1_1.json", "RFC8152/Appendix_C_1_2.json", "mac-tests/HMac-01.json", "hmac-examples/HMac-05.json"} {
		t.Run(path, func(t *testing.T) {
			token, v := loadMulti(t, path)
			msg, err := parseMulti(token)
			if err != nil {
				t.Fatalf("parseMulti: %v", err)
			}
			if msg.coseTag == tagMac {
				got, _ := cbor.Marshal([]any{"MAC", nonNil(msg.protectedRaw), []byte{}, nonNil(msg.payload)})
				if want := mustHexT(t, v.Intermediates.ToMacHex); !bytes.Equal(got, want) {
					t.Fatalf("MAC_structure\n got %x\nwant %x", got, want)
				}
				return
			}
			if len(msg.parties) != len(v.Intermediates.Signers) {
				t.Fatalf("%d signers, vector has %d", len(msg.parties), len(v.Intermediates.Signers))
			}
			for i, p := range msg.parties {
				got, _ := cbor.Marshal([]any{"Signature", nonNil(msg.protectedRaw), nonNil(p.protectedRaw), []byte{}, nonNil(msg.payload)})
				if want := mustHexT(t, v.Intermediates.Signers[i].ToBeSignHex); !bytes.Equal(got, want) {
					t.Fatalf("signer %d Sig_structure\n got %x\nwant %x", i, got, want)
				}
			}
		})
	}
}

// TestMultiVectors runs every vector through VerifyMessage. A nil want means it must verify. Vectors the working
// group marks as passing are refused here on purpose: sign-pass-01 replaces an empty protected header with an
// encoded empty map after signing, and RFC 9052 Section 4.4 builds the signed bytes from the header as received;
// mac-pass-01 carries alg in the unprotected header (decision 0009); the -02 vectors need external data, which this
// package never supplies; the -03 vectors are untagged (decision 0029); and ecdsa-01 carries a content type header,
// which decision 0008 does not understand.
func TestMultiVectors(t *testing.T) {
	cases := []struct {
		path   string
		macAlg Algorithm
		want   error
	}{
		{"RFC8152/Appendix_C_1_1.json", 0, nil},
		{"RFC8152/Appendix_C_1_2.json", 0, nil}, // the P-521 signer is unknown, so skipped
		{"mac-tests/HMac-01.json", HMAC256x256, nil},
		{"hmac-examples/HMac-05.json", HMAC256x64, nil},

		{"sign-tests/sign-pass-01.json", 0, ErrVerification},
		{"sign-tests/sign-pass-02.json", 0, ErrVerification},
		{"sign-tests/sign-pass-03.json", 0, ErrMalformed},
		{"sign-tests/ecdsa-01.json", 0, ErrUnsupported},
		{"mac-tests/mac-pass-01.json", HMAC256x256, ErrMalformed},
		{"mac-tests/mac-pass-02.json", HMAC256x256, ErrMalformed},
		{"mac-tests/mac-pass-03.json", HMAC256x256, ErrMalformed},

		{"sign-tests/sign-fail-01.json", 0, ErrMalformed},
		{"sign-tests/sign-fail-02.json", 0, ErrVerification},
		{"sign-tests/sign-fail-03.json", 0, ErrUnsupported},
		{"sign-tests/sign-fail-04.json", 0, ErrUnsupported},
		{"sign-tests/sign-fail-06.json", 0, ErrUnsupported},
		{"sign-tests/sign-fail-07.json", 0, ErrVerification},
		{"mac-tests/mac-fail-01.json", HMAC256x256, ErrMalformed},
		{"mac-tests/mac-fail-02.json", HMAC256x256, ErrVerification},
		{"mac-tests/mac-fail-03.json", HMAC256x256, ErrUnsupported},
		{"mac-tests/mac-fail-04.json", HMAC256x256, ErrUnsupported},
		{"mac-tests/mac-fail-06.json", HMAC256x256, ErrUnsupported},
		{"mac-tests/mac-fail-07.json", HMAC256x256, ErrVerification},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			token, v := loadMulti(t, tc.path)
			msg, err := VerifyMessage(token, lookupFor(t, v, tc.macAlg))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("VerifyMessage: %v", err)
				}
				if !bytes.Equal(msg.Payload, []byte("This is the content.")) {
					t.Fatalf("payload %q", msg.Payload)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want an error wrapping %v", err, tc.want)
			}
		})
	}
}

// TestMultiPolicy checks decision 0029's policy on RFC 8152 C.1.2, which has an ES256 signer "11" and a P-521
// signer this package cannot verify.
func TestMultiPolicy(t *testing.T) {
	token, v := loadMulti(t, "RFC8152/Appendix_C_1_2.json")
	known := lookupFor(t, v, 0)

	t.Run("the verifying signer is reported", func(t *testing.T) {
		msg, err := VerifyMessage(token, known)
		if err != nil || string(msg.KID) != "11" || msg.Algorithm != ES256 {
			t.Fatalf("got %+v, %v", msg, err)
		}
	})
	t.Run("a known signer whose signature fails refuses the message", func(t *testing.T) {
		bad := bytes.Clone(token)
		i := bytes.Index(bad, mustHexT(t, "E2AEAFD40D69D19D"))
		if i < 0 {
			t.Fatal("signature not found")
		}
		bad[i] ^= 1
		if _, err := VerifyMessage(bad, known); !errors.Is(err, ErrVerification) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a known key for a signer whose algorithm is unsupported refuses the message", func(t *testing.T) {
		both := func(kid []byte) (Key, error) {
			k, err := known([]byte("11"))
			return k, err // every kid resolves, so the ES512 signer is known and must be checked
		}
		if _, err := VerifyMessage(token, both); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no known signer", func(t *testing.T) {
		none := func([]byte) (Key, error) { return Key{}, errors.New("unknown") }
		if _, err := VerifyMessage(token, none); !errors.Is(err, ErrVerification) {
			t.Fatalf("got %v", err)
		}
	})
}

// TestMultiRules checks the structural rules decision 0029 adds.
func TestMultiRules(t *testing.T) {
	enc := func(v any) []byte {
		b, err := cbor.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	recipient := []any{[]byte{}, map[int64]any{1: -6, 4: []byte("k")}, []byte{}}
	mac := func(protected []byte, unprotected map[int64]any, recipients []any) []byte {
		return enc(cbor.Tag{Number: 97, Content: []any{protected, unprotected, []byte("x"), make([]byte, 32), recipients}})
	}
	lookup := func([]byte) (Key, error) { return Key{Algorithm: HMAC256x256, Material: []byte("secret")}, nil }
	for name, tc := range map[string]struct {
		token []byte
		want  error
	}{
		"kid in the body": {mac(enc(map[int64]any{1: 5}), map[int64]any{4: []byte("k")}, []any{recipient}), ErrMalformed},
		"no recipients":   {mac(enc(map[int64]any{1: 5}), map[int64]any{}, []any{}), ErrMalformed},
		"a key-wrapping recipient": {mac(enc(map[int64]any{1: 5}), map[int64]any{},
			[]any{[]any{[]byte{}, map[int64]any{1: -3, 4: []byte("k")}, []byte("wrapped")}}), ErrMalformed},
		"a recipient with a protected header": {mac(enc(map[int64]any{1: 5}), map[int64]any{},
			[]any{[]any{enc(map[int64]any{1: -6}), map[int64]any{4: []byte("k")}, []byte{}}}), ErrMalformed},
		"a recipient of a recipient": {mac(enc(map[int64]any{1: 5}), map[int64]any{},
			[]any{append(append([]any{}, recipient...), []any{})}), ErrUnsupported},
		"alg in a COSE_Sign body": {enc(cbor.Tag{Number: 98, Content: []any{enc(map[int64]any{1: -7}), map[int64]any{}, []byte("x"),
			[]any{[]any{enc(map[int64]any{1: -7}), map[int64]any{4: []byte("k")}, make([]byte, 64)}}}}), ErrMalformed},
		"a wrong MAC tag":                        {mac(enc(map[int64]any{1: 5}), map[int64]any{}, []any{recipient}), ErrVerification},
		"an untagged COSE_Mac is not recognised": {enc([]any{enc(map[int64]any{1: 5}), map[int64]any{}, []byte("x"), make([]byte, 32), []any{recipient}}), ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyMessage(tc.token, lookup); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want an error wrapping %v", err, tc.want)
			}
		})
	}
}
