package cat_test

// draft-ietf-moq-c4m's Appendix A vectors (decision 0033): the token-validation and token-structure vectors, which
// carry the COSE typ header "CAT". Source and licence: testdata/c4m/SOURCE.md.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

type c4mVectors struct {
	Keys struct {
		HMAC string `json:"hmac_sha256"`
		X    string `json:"es256_public_key_x"`
		Y    string `json:"es256_public_key_y"`
	} `json:"keys"`
	TokenValidation []struct {
		ID         string `json:"id"`
		Token      string `json:"token"`
		Validation struct {
			ReferenceTime     int64    `json:"reference_time"`
			ExpectedIssuers   []string `json:"expected_issuers"`
			ExpectedAudiences []string `json:"expected_audiences"`
			ExpectedResult    string   `json:"expected_result"`
			ExpectedError     string   `json:"expected_error"`
			WrongKeyHex       string   `json:"wrong_key_hex"`
			VerifierAlgorithm int64    `json:"verifier_algorithm_id"`
		} `json:"validation"`
	} `json:"token_validation"`
	TokenStructure []struct {
		ID          string `json:"id"`
		AlgorithmID int64  `json:"algorithm_id"`
		PayloadHex  string `json:"payload_cbor_hex"`
		KeyHex      string `json:"key_hex"`
		CoseB64     string `json:"cose_b64"`
	} `json:"token_structure"`
}

func loadC4M(t *testing.T) c4mVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/c4m/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v c4mVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (v c4mVectors) es256(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	pt := append(append([]byte{4}, fromHex(t, v.Keys.X)...), fromHex(t, v.Keys.Y)...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// c4mErrors maps the draft's error names to the errors this package returns for the same refusal.
var c4mErrors = map[string]error{
	"TokenExpired":                cat.ErrExpired,
	"TokenNotYetValid":            cat.ErrNotYetValid,
	"InvalidIssuer":               cat.ErrIssuer,
	"InvalidAudience":             cat.ErrAudience,
	"SignatureVerificationFailed": cwt.ErrVerification,
	"InvalidTokenFormat":          cwt.ErrMalformed,
}

// c4mDifferences are the vectors where this package's verdict or error kind differs from the draft's, and why. Each
// asserts this package's outcome; the difference is recorded in the measurements (task 67).
var c4mDifferences = map[string]struct {
	want error // nil means accepted
	why  string
}{
	// The draft calls this an invalid format. Here the key fixes the algorithm (decision 0015), so a COSE_Mac0 under
	// an ES256 key fails as an alg that does not match its key: refused either way, with a different error kind.
	"invalid_algorithm_mismatch": {cwt.ErrVerification, "alg does not match the key's algorithm"},
	// The draft expects this token to be valid, but its catnip names a full IPv4 address without encryption, which
	// CTA-5007-B section 4.6.9 makes invalid. This package follows CTA-5007-B.
	"token_hmac_full": {cwt.ErrMalformed, "an unencrypted catnip address (CTA-5007-B 4.6.9)"},
}

func TestC4MTokenValidation(t *testing.T) {
	v := loadC4M(t)
	for _, tc := range v.TokenValidation {
		t.Run(tc.ID, func(t *testing.T) {
			val := tc.Validation
			key := cwt.Key{Algorithm: cwt.HMAC256x256, Material: fromHex(t, v.Keys.HMAC)}
			if val.WrongKeyHex != "" {
				key.Material = fromHex(t, val.WrongKeyHex)
			}
			if val.VerifierAlgorithm == int64(cwt.ES256) {
				key = cwt.Key{Algorithm: cwt.ES256, Material: v.es256(t)}
			}
			issuer := "https://auth.example.com"
			if len(val.ExpectedIssuers) > 0 {
				issuer = val.ExpectedIssuers[0]
			}
			now := val.ReferenceTime
			if now == 0 {
				now = 1700003600
			}
			validator := &cat.Validator{
				Keys:      func([]byte) (cat.Key, error) { return cat.Key{Key: key, Issuer: issuer}, nil },
				Audiences: val.ExpectedAudiences,
				Now:       func() time.Time { return time.Unix(now, 0) },
			}
			if val.ExpectedAudiences == nil {
				validator.Audiences = []string{"https://relay.example.com"}
			}
			_, err := validator.Validate(tc.Token)
			if d, ok := c4mDifferences[tc.ID]; ok {
				if !errors.Is(err, d.want) {
					t.Fatalf("got %v, want %v: %s", err, d.want, d.why)
				}
				return
			}
			if val.ExpectedResult == "valid" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			want, ok := c4mErrors[val.ExpectedError]
			if !ok {
				t.Fatalf("no mapping for the draft's error %q", val.ExpectedError)
			}
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v for the draft's %s", err, want, val.ExpectedError)
			}
		})
	}
}

func TestC4MTokenStructure(t *testing.T) {
	v := loadC4M(t)
	for _, tc := range v.TokenStructure {
		t.Run(tc.ID, func(t *testing.T) {
			var claims map[int64]any
			if err := cbor.Unmarshal(fromHex(t, tc.PayloadHex), &claims); err != nil {
				t.Fatal(err)
			}
			issuer, _ := claims[1].(string)
			var audiences []string
			if list, ok := claims[3].([]any); ok {
				for _, a := range list {
					s, _ := a.(string)
					audiences = append(audiences, s)
				}
			}
			key := cwt.Key{Algorithm: cwt.HMAC256x256, Material: fromHex(t, tc.KeyHex)}
			if tc.AlgorithmID == int64(cwt.ES256) {
				key = cwt.Key{Algorithm: cwt.ES256, Material: v.es256(t)}
			}
			validator := &cat.Validator{
				Keys:      func([]byte) (cat.Key, error) { return cat.Key{Key: key, Issuer: issuer}, nil },
				Audiences: audiences,
				Now:       func() time.Time { return time.Unix(1700003600, 0) },
			}
			tok, err := validator.Validate(tc.CoseB64)
			if d, ok := c4mDifferences[tc.ID]; ok {
				if !errors.Is(err, d.want) {
					t.Fatalf("got %v, want %v: %s", err, d.want, d.why)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if tok.Type != "CAT" {
				t.Fatalf("Type = %q, want CAT", tok.Type)
			}
		})
	}
}

func TestTypHeader(t *testing.T) {
	payload := enc(t, map[any]any{1: "issuer"})
	token := func(protected map[int64]any, unprotected map[int64]any) string {
		return mac0Header(t, enc(t, protected), unprotected, payload)
	}
	cases := []struct {
		name  string
		token string
		types []string
		want  error
	}{
		{"no typ", token(map[int64]any{1: 5}, map[int64]any{}), nil, nil},
		{"typ CAT, protected", token(map[int64]any{1: 5, 16: "CAT"}, map[int64]any{}), nil, nil},
		{"typ CAT, unprotected", token(map[int64]any{1: 5}, map[int64]any{16: "CAT"}), nil, nil},
		{"a DPoP proof's typ", token(map[int64]any{1: 5, 16: "dpop-proof+cwt"}, map[int64]any{}), nil, cwt.ErrUnsupported},
		{"typ in a different case", token(map[int64]any{1: 5, 16: "cat"}, map[int64]any{}), nil, cwt.ErrUnsupported},
		{"a content-format number", token(map[int64]any{1: 5, 16: 61}, map[int64]any{}), nil, cwt.ErrUnsupported},
		{"a type the recipient lists", token(map[int64]any{1: 5, 16: "application/cwt"}, map[int64]any{}), []string{"application/cwt"}, nil},
		{"CAT, when the list does not name it", token(map[int64]any{1: 5, 16: "CAT"}, map[int64]any{}), []string{"application/cwt"}, cwt.ErrUnsupported},
		{"typ of the wrong CBOR type", token(map[int64]any{1: 5, 16: []byte("CAT")}, map[int64]any{}), nil, cwt.ErrMalformed},
		{"typ in both headers", token(map[int64]any{1: 5, 16: "CAT"}, map[int64]any{16: "CAT"}), nil, cwt.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := validator()
			v.Types = tc.types
			_, err := v.Validate(tc.token)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// mac0Header builds an HMAC 256/256 COSE_Mac0 CAT with the given protected bytes and unprotected header.
func mac0Header(t *testing.T, protected []byte, unprotected map[int64]any, payload []byte) string {
	t.Helper()
	return mac0{protected: protected, unprotectedExtra: unprotected, payload: payload}.text(t)
}
