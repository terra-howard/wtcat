package cwt_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

// lookupOne returns a KeyLookup that hands out one key, and records each kid it was asked for.
func lookupOne(key cwt.Key, asked *[][]byte) cwt.KeyLookup {
	return func(kid []byte) (cwt.Key, error) {
		if asked != nil {
			*asked = append(*asked, kid)
		}
		return key, nil
	}
}

func hmacKey(alg cwt.Algorithm) cwt.Key { return cwt.Key{Algorithm: alg, Material: testKey} }

// noAlgMac0 is defaultMac0 with no alg header at all: a zero-length protected header.
func noAlgMac0(t *testing.T) mac0Token {
	m := defaultMac0(t)
	m.protectedRaw = []byte{}
	return m
}

// ps256Token signs a payload as a tagged COSE_Sign1 with PS256.
func ps256Token(t *testing.T, priv *rsa.PrivateKey, protected map[int64]any) []byte {
	t.Helper()
	protectedRaw := []byte{}
	if protected != nil {
		protectedRaw = encode(t, protected)
	}
	payload := encode(t, map[int64]any{1: "issuer"})
	digest := sha256.Sum256(encode(t, []any{"Signature1", protectedRaw, []byte{}, payload}))
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatal(err)
	}
	return encode(t, cbor.Tag{Number: 18, Content: []any{protectedRaw, map[int64]any{}, payload, sig}})
}

func TestVerifyMessageReturnsTheVerifiedParts(t *testing.T) {
	m := defaultMac0(t)
	m.unprotected = map[int64]any{4: []byte("key-1")}
	var asked [][]byte
	msg, err := cwt.VerifyMessage(m.build(t), lookupOne(hmacKey(cwt.HMAC256x256), &asked))
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if msg.Algorithm != cwt.HMAC256x256 {
		t.Errorf("Algorithm = %d, want %d", msg.Algorithm, cwt.HMAC256x256)
	}
	if string(msg.KID) != "key-1" {
		t.Errorf("KID = %q, want key-1", msg.KID)
	}
	if !bytes.Equal(msg.Protected, m.protectedRaw) {
		t.Errorf("Protected = %x, want %x", msg.Protected, m.protectedRaw)
	}
	if !bytes.Equal(msg.Payload, m.payload.([]byte)) {
		t.Errorf("Payload = %x, want %x", msg.Payload, m.payload)
	}
	if len(asked) != 1 || string(asked[0]) != "key-1" {
		t.Errorf("lookup was asked for %q, want one call for key-1", asked)
	}
}

func TestVerifyMessageAcceptsAMissingAlgUsingTheKeysAlgorithm(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	short := noAlgMac0(t)
	short.tagLen = 8
	untagged := noAlgMac0(t)
	untagged.coseTag = 0
	cases := []struct {
		name  string
		token []byte
		key   cwt.Key
	}{
		{"HMAC 256/256", noAlgMac0(t).build(t), hmacKey(cwt.HMAC256x256)},
		{"HMAC 256/256, untagged", untagged.build(t), hmacKey(cwt.HMAC256x256)},
		{"HMAC 256/64", short.build(t), hmacKey(cwt.HMAC256x64)},
		{"ES256, empty protected map", es256Token(t, ecKey, map[int64]any{}, 64), cwt.Key{Algorithm: cwt.ES256, Material: &ecKey.PublicKey}},
		{"PS256, zero-length protected header", ps256Token(t, rsaKey, nil), cwt.Key{Algorithm: cwt.PS256, Material: &rsaKey.PublicKey}},
		{"PS256, alg present", ps256Token(t, rsaKey, map[int64]any{1: -37}), cwt.Key{Algorithm: cwt.PS256, Material: &rsaKey.PublicKey}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := cwt.VerifyMessage(tc.token, lookupOne(tc.key, nil))
			if err != nil {
				t.Fatalf("VerifyMessage: %v", err)
			}
			if msg.Algorithm != tc.key.Algorithm {
				t.Errorf("Algorithm = %d, want %d", msg.Algorithm, tc.key.Algorithm)
			}
		})
	}
}

func TestVerifyMessageVerifiesTheRFCTokens(t *testing.T) {
	keys := rfcKeys(t)
	lookup := func(kid []byte) (cwt.Key, error) {
		if string(kid) == "Symmetric256" {
			material, err := keys(kid, cwt.HMAC256x64)
			return cwt.Key{Algorithm: cwt.HMAC256x64, Material: material}, err
		}
		material, err := keys(kid, cwt.ES256)
		return cwt.Key{Algorithm: cwt.ES256, Material: material}, err
	}
	for name, token := range map[string]string{"A.3": seedSignedA3, "A.4": seedMacedA4} {
		t.Run(name, func(t *testing.T) {
			msg, err := cwt.VerifyMessage(fromHex(t, token), lookup)
			if err != nil {
				t.Fatalf("VerifyMessage: %v", err)
			}
			if !bytes.Equal(msg.Payload, fromHex(t, seedClaimsA1)) {
				t.Errorf("payload is not RFC 8392 A.1's claims set")
			}
		})
	}
}

func TestVerifyMessageLeavesThePayloadUninterpreted(t *testing.T) {
	m := defaultMac0(t)
	m.payload = encode(t, "not a claims set")
	msg, err := cwt.VerifyMessage(m.build(t), lookupOne(hmacKey(cwt.HMAC256x256), nil))
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if !bytes.Equal(msg.Payload, m.payload.([]byte)) {
		t.Errorf("Payload = %x, want %x", msg.Payload, m.payload)
	}
}

func TestVerifyMessageRejects(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	esKey := cwt.Key{Algorithm: cwt.ES256, Material: &ecKey.PublicKey}
	tampered := noAlgMac0(t).build(t)
	tampered[len(tampered)-1] ^= 0x01

	cases := []struct {
		name  string
		token []byte
		key   cwt.Key
		want  error
	}{
		{"alg header names another algorithm than the key's", defaultMac0(t).build(t), hmacKey(cwt.HMAC256x64), cwt.ErrVerification},
		{"key's algorithm is a signature algorithm for a MAC token", noAlgMac0(t).build(t), cwt.Key{Algorithm: cwt.ES256, Material: testKey}, cwt.ErrMalformed},
		{"key's algorithm is a MAC algorithm for a signed token", es256Token(t, ecKey, map[int64]any{}, 64), hmacKey(cwt.HMAC256x256), cwt.ErrMalformed},
		{"key's algorithm is not supported", noAlgMac0(t).build(t), cwt.Key{Algorithm: 999, Material: testKey}, cwt.ErrUnsupported},
		{"HMAC key material is not a []byte", noAlgMac0(t).build(t), cwt.Key{Algorithm: cwt.HMAC256x256, Material: &ecKey.PublicKey}, cwt.ErrVerification},
		{"ES256 key material is a []byte", es256Token(t, ecKey, map[int64]any{}, 64), cwt.Key{Algorithm: cwt.ES256, Material: testKey}, cwt.ErrVerification},
		{"ES256 key material is nil", es256Token(t, ecKey, map[int64]any{}, 64), cwt.Key{Algorithm: cwt.ES256}, cwt.ErrVerification},
		{"MAC tag changed", tampered, hmacKey(cwt.HMAC256x256), cwt.ErrVerification},
		{"HMAC 256/64 key for a 32-byte tag", noAlgMac0(t).build(t), hmacKey(cwt.HMAC256x64), cwt.ErrVerification},
		{"wrong ES256 key", es256Token(t, ecKey, map[int64]any{}, 64), func() cwt.Key {
			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return cwt.Key{Algorithm: cwt.ES256, Material: &other.PublicKey}
		}(), cwt.ErrVerification},
		{"alg only in the unprotected header", func() []byte {
			m := noAlgMac0(t)
			m.unprotected = map[int64]any{1: 5}
			return m.build(t)
		}(), hmacKey(cwt.HMAC256x256), cwt.ErrMalformed},
		{"detached payload", func() []byte {
			m := noAlgMac0(t)
			m.payload = nil
			return m.build(t)
		}(), hmacKey(cwt.HMAC256x256), cwt.ErrUnsupported},
		{"not CBOR", []byte{0xff}, esKey, cwt.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cwt.VerifyMessage(tc.token, lookupOne(tc.key, nil)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want an error wrapping %v", err, tc.want)
			}
		})
	}
}

func TestVerifyMessageRefusesAnUnknownAlgBeforeKeyLookup(t *testing.T) {
	m := defaultMac0(t)
	m.protectedRaw = encode(t, map[int64]any{1: 999})
	var asked [][]byte
	_, err := cwt.VerifyMessage(m.build(t), lookupOne(hmacKey(cwt.HMAC256x256), &asked))
	if !errors.Is(err, cwt.ErrUnsupported) {
		t.Fatalf("got %v, want an error wrapping cwt.ErrUnsupported", err)
	}
	if len(asked) != 0 {
		t.Errorf("key lookup was called %d times, want 0", len(asked))
	}
}

func TestVerifyMessageChecksTheTagAgainstAnAlgHeaderBeforeKeyLookup(t *testing.T) {
	m := defaultMac0(t)
	m.coseTag = 18 // COSE_Sign1, with an HMAC alg header
	var asked [][]byte
	_, err := cwt.VerifyMessage(m.build(t), lookupOne(hmacKey(cwt.HMAC256x256), &asked))
	if !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("got %v, want an error wrapping cwt.ErrMalformed", err)
	}
	if len(asked) != 0 {
		t.Errorf("key lookup was called %d times, want 0", len(asked))
	}
}

func TestVerifyMessageWrapsLookupErrors(t *testing.T) {
	sentinel := errors.New("no such key")
	_, err := cwt.VerifyMessage(noAlgMac0(t).build(t), func([]byte) (cwt.Key, error) { return cwt.Key{}, sentinel })
	if !errors.Is(err, cwt.ErrVerification) || !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want an error wrapping both cwt.ErrVerification and the lookup's error", err)
	}
}

func TestVerifyMessageNeedsALookup(t *testing.T) {
	_, err := cwt.VerifyMessage(noAlgMac0(t).build(t), nil)
	if err == nil {
		t.Fatal("got nil error for a nil lookup")
	}
	for _, kind := range []error{cwt.ErrVerification, cwt.ErrMalformed, cwt.ErrUnsupported} {
		if errors.Is(err, kind) {
			t.Fatalf("a configuration error wraps %v; it should not look like a token error", kind)
		}
	}
}

func TestVerifyMac0StillRequiresAlg(t *testing.T) {
	if _, err := cwt.VerifyMac0(noAlgMac0(t).build(t), testKey); !errors.Is(err, cwt.ErrMalformed) {
		t.Fatalf("got %v, want an error wrapping cwt.ErrMalformed", err)
	}
}

func FuzzVerifyMessage(f *testing.F) {
	seed(f, seedSignedA3, seedMacedA4)
	f.Fuzz(func(t *testing.T, token []byte) {
		keys := rfcKeys(t)
		lookup := func(kid []byte) (cwt.Key, error) {
			if string(kid) == "Symmetric256" {
				material, err := keys(kid, cwt.HMAC256x64)
				return cwt.Key{Algorithm: cwt.HMAC256x64, Material: material}, err
			}
			material, err := keys(kid, cwt.ES256)
			return cwt.Key{Algorithm: cwt.ES256, Material: material}, err
		}
		msg, err := cwt.VerifyMessage(token, lookup)
		checkClassified(t, err, cwt.ErrVerification, cwt.ErrMalformed, cwt.ErrUnsupported)
		if err == nil && msg == nil {
			t.Fatal("nil message with nil error")
		}
	})
}
