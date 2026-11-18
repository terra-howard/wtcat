package cat_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

// The claim keys of actx and ath are unassigned (decision 0038), so these tests agree on two of their own.
const actxKey, athKey = -70001, -70002

// Two thumbprints of the Appendix A ES256 test key, from draft-ietf-moq-c4m itself (testdata/c4m/SOURCE.md): the
// ckt of the section "DPoP for MOQT" example, and the jkt of the "DPoP Binding" vector dpop_jwk_binding.
var (
	draftCKT = "750ca40795ab23e51a75dc76fa12c052f6f6c57ba8a732337b91f096592b6ef6"
	draftJKT = "0cebf1bc9880748a95588905b79843b42ba75cb174055e3e246bf87fe00b4a6d"
)

func (v c4mVectors) es256Private(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), fromHex(t, v.Keys.D))
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func coseKey(pub *ecdsa.PublicKey) map[int64]any {
	pt, err := pub.Bytes()
	if err != nil {
		panic(err)
	}
	return map[int64]any{1: 2, -1: 1, -2: pt[1:33], -3: pt[33:]}
}

// dpopCase builds a token and an MOQT DPoP proof for it, each changeable before it is encoded.
type dpopCase struct {
	priv     *ecdsa.PrivateKey // the key in kccs
	signer   *ecdsa.PrivateKey // the key that signs; priv when nil
	cnf      map[int64]any
	extra    map[any]any // more token claims
	header   map[int64]any
	unprot   map[int64]any
	claims   map[any]any
	untagged bool
	corrupt  bool
}

func newDPoPCase(t *testing.T) *dpopCase {
	priv := loadC4M(t).es256Private(t)
	return &dpopCase{
		priv:   priv,
		cnf:    map[int64]any{5: fromHex(t, draftCKT)},
		header: map[int64]any{1: -7, 16: "dpop-proof+cwt", 14: map[int64]any{8: map[int64]any{1: coseKey(&priv.PublicKey)}}},
		unprot: map[int64]any{},
		claims: map[any]any{
			7:       []byte("proof-1"),
			6:       testNow.Unix(),
			actxKey: map[any]any{0: "moqt", 1: 4, 2: []any{[]byte("cdn"), []byte("example.com")}, 3: []byte("/sports/live")},
		},
	}
}

func (d *dpopCase) token(t *testing.T) string {
	claims := map[any]any{8: d.cnf, moqtKey: map[any]any{0: []any{[]any{[]any{1, 4, 7}}}}}
	maps.Copy(claims, d.extra)
	return claimsToken(t, claims)
}

// proof signs the proof for token, setting ath to the hash of the token's bytes unless the case set its own.
func (d *dpopCase) proof(t *testing.T, token string) []byte {
	claims := maps.Clone(d.claims)
	if _, ok := claims[athKey]; !ok {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		claims[athKey] = sum[:]
	}
	for k, v := range claims {
		if v == nil {
			delete(claims, k)
		}
	}
	header := maps.Clone(d.header)
	maps.DeleteFunc(header, func(_ int64, v any) bool { return v == nil })
	protected := enc(t, header)
	payload := enc(t, claims)
	signer := d.signer
	if signer == nil {
		signer = d.priv
	}
	digest := sha256.Sum256(enc(t, []any{"Signature1", protected, []byte{}, payload}))
	r, s, err := ecdsa.Sign(rand.Reader, signer, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if d.corrupt {
		sig[10] ^= 1
	}
	body := []any{protected, d.unprot, payload, sig}
	if d.untagged {
		return enc(t, body)
	}
	return enc(t, cbor.Tag{Number: 18, Content: body})
}

func dpopValidator() *cat.Validator {
	v := validator()
	v.ActxKey, v.AthKey = actxKey, athKey
	return v
}

func sportsRequest(proof []byte) *cat.Request {
	r := moqtRequest(4, []string{"cdn", "example.com"}, text("/sports/live"))
	r.MOQT.Proof = proof
	return r
}

// TestMOQTDPoP checks decision 0038's relay checks, one change from a good token and proof at a time.
func TestMOQTDPoP(t *testing.T) {
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actx := func(d *dpopCase) map[any]any { return d.claims[actxKey].(map[any]any) }
	cases := []struct {
		name   string
		change func(*dpopCase)
		req    func([]byte) *cat.Request
		want   error
	}{
		{"a good proof, by ckt", func(*dpopCase) {}, nil, nil},
		{"a good proof, by jkt", func(d *dpopCase) { d.cnf = map[int64]any{323: fromHex(t, draftJKT)} }, nil, nil},
		{"a good proof, by both", func(d *dpopCase) { d.cnf[323] = fromHex(t, draftJKT) }, nil, nil},
		{"an untagged proof", func(d *dpopCase) { d.untagged = true }, nil, nil},
		{"iat in the future, within the window", func(d *dpopCase) { d.claims[6] = testNow.Unix() + 60 }, nil, nil},
		{"iat in the past, within the window", func(d *dpopCase) { d.claims[6] = testNow.Unix() - 60 }, nil, nil},
		{"iat within catdpop's longer window", func(d *dpopCase) {
			d.claims[6] = testNow.Unix() - 200
			d.extra = map[any]any{321: map[any]any{0: 300}}
		}, nil, nil},
		{"SETUP, with no namespace or track", func(d *dpopCase) { d.claims[actxKey] = map[any]any{0: "moqt", 1: 1} },
			func(p []byte) *cat.Request { r := moqtRequest(1, nil, nil); r.MOQT.Proof = p; return r }, nil},
		{"no proof", func(*dpopCase) {}, func([]byte) *cat.Request { return sportsRequest(nil) }, cat.ErrProof},
		{"a proof that is not CBOR", func(*dpopCase) {}, func([]byte) *cat.Request { return sportsRequest([]byte{0xff}) }, cat.ErrProof},
		{"a proof that is not a COSE_Sign1", func(*dpopCase) {}, func([]byte) *cat.Request { return sportsRequest([]byte{0x80}) }, cat.ErrProof},
		{"ckt of another key", func(d *dpopCase) { d.cnf[5] = make([]byte, 32) }, nil, cat.ErrProof},
		{"jkt of another key beside the right ckt", func(d *dpopCase) { d.cnf[323] = make([]byte, 32) }, nil, cat.ErrProof},
		{"signed by another key", func(d *dpopCase) { d.signer = other }, nil, cat.ErrProof},
		{"a corrupted signature", func(d *dpopCase) { d.corrupt = true }, nil, cat.ErrProof},
		{"another key in kccs, matching nothing", func(d *dpopCase) {
			d.header[14] = map[int64]any{8: map[int64]any{1: coseKey(&other.PublicKey)}}
			d.signer = other
		}, nil, cat.ErrProof},
		{"no typ", func(d *dpopCase) { d.header[16] = nil }, nil, cat.ErrProof},
		{"a CAT's typ", func(d *dpopCase) { d.header[16] = "CAT" }, nil, cat.ErrProof},
		{"no alg", func(d *dpopCase) { d.header[1] = nil }, nil, cat.ErrProof},
		{"a symmetric alg", func(d *dpopCase) { d.header[1] = 5 }, nil, cat.ErrProof},
		{"ES384, not supported yet", func(d *dpopCase) { d.header[1] = -35 }, nil, cat.ErrProof},
		{"no kccs", func(d *dpopCase) { d.header[14] = nil }, nil, cat.ErrProof},
		{"kccs only in the unprotected header", func(d *dpopCase) {
			d.unprot[14] = d.header[14]
			d.header[14] = nil
		}, nil, cat.ErrProof},
		{"kccs without cnf", func(d *dpopCase) { d.header[14] = map[int64]any{1: "issuer"} }, nil, cat.ErrProof},
		{"kccs cnf without a COSE_Key", func(d *dpopCase) { d.header[14] = map[int64]any{8: map[int64]any{3: []byte("kid")}} }, nil, cat.ErrProof},
		{"a COSE_Key with its private part", func(d *dpopCase) {
			k := coseKey(&d.priv.PublicKey)
			k[-4] = d.priv.D.FillBytes(make([]byte, 32))
			d.header[14] = map[int64]any{8: map[int64]any{1: k}}
		}, nil, cat.ErrProof},
		{"an OKP key", func(d *dpopCase) {
			k := coseKey(&d.priv.PublicKey)
			k[1] = 1
			d.header[14] = map[int64]any{8: map[int64]any{1: k}}
		}, nil, cat.ErrProof},
		{"a P-384 curve label", func(d *dpopCase) {
			k := coseKey(&d.priv.PublicKey)
			k[-1] = 2
			d.header[14] = map[int64]any{8: map[int64]any{1: k}}
		}, nil, cat.ErrProof},
		{"an x of the wrong length", func(d *dpopCase) {
			k := coseKey(&d.priv.PublicKey)
			k[-2] = k[-2].([]byte)[1:]
			d.header[14] = map[int64]any{8: map[int64]any{1: k}}
		}, nil, cat.ErrProof},
		{"a point not on the curve", func(d *dpopCase) {
			k := coseKey(&d.priv.PublicKey)
			y := append([]byte{}, k[-3].([]byte)...)
			y[31] ^= 1
			k[-3] = y
			d.header[14] = map[int64]any{8: map[int64]any{1: k}}
		}, nil, cat.ErrProof},
		{"ath of another token", func(d *dpopCase) { d.claims[athKey] = make([]byte, 32) }, nil, cat.ErrProof},
		{"no ath", func(d *dpopCase) { d.claims[athKey] = nil }, nil, cat.ErrProof},
		{"iat too far in the past", func(d *dpopCase) { d.claims[6] = testNow.Unix() - 61 }, nil, cat.ErrProof},
		{"iat too far in the future", func(d *dpopCase) { d.claims[6] = testNow.Unix() + 61 }, nil, cat.ErrProof},
		{"no iat", func(d *dpopCase) { d.claims[6] = nil }, nil, cat.ErrProof},
		{"a floating-point iat", func(d *dpopCase) { d.claims[6] = float64(testNow.Unix()) + 0.5 }, nil, cat.ErrProof},
		{"no cti", func(d *dpopCase) { d.claims[7] = nil }, nil, cat.ErrProof},
		{"an empty cti", func(d *dpopCase) { d.claims[7] = []byte{} }, nil, cat.ErrProof},
		{"a text cti", func(d *dpopCase) { d.claims[7] = "proof-1" }, nil, cat.ErrProof},
		{"no actx", func(d *dpopCase) { d.claims[actxKey] = nil }, nil, cat.ErrProof},
		{"actx not a map", func(d *dpopCase) { d.claims[actxKey] = []any{"moqt", 4} }, nil, cat.ErrProof},
		{"actx for another protocol", func(d *dpopCase) { actx(d)[0] = "http" }, nil, cat.ErrProof},
		{"actx with no type", func(d *dpopCase) { delete(actx(d), 0) }, nil, cat.ErrProof},
		{"actx for another action", func(d *dpopCase) { actx(d)[1] = 7 }, nil, cat.ErrProof},
		{"actx with no action", func(d *dpopCase) { delete(actx(d), 1) }, nil, cat.ErrProof},
		{"actx for another namespace", func(d *dpopCase) { actx(d)[2] = []any{[]byte("cdn"), []byte("example.org")} }, nil, cat.ErrProof},
		{"actx with a longer namespace", func(d *dpopCase) { actx(d)[2] = []any{[]byte("cdn"), []byte("example.com"), []byte("x")} }, nil, cat.ErrProof},
		{"actx with no namespace", func(d *dpopCase) { delete(actx(d), 2) }, nil, cat.ErrProof},
		{"actx with a text namespace field", func(d *dpopCase) { actx(d)[2] = []any{"cdn", []byte("example.com")} }, nil, cat.ErrProof},
		{"actx for another track", func(d *dpopCase) { actx(d)[3] = []byte("/sports/replay") }, nil, cat.ErrProof},
		{"actx with no track", func(d *dpopCase) { delete(actx(d), 3) }, nil, cat.ErrProof},
		{"actx with an empty track, the request with none", func(d *dpopCase) { actx(d)[3] = []byte{} },
			func(p []byte) *cat.Request {
				r := moqtRequest(4, []string{"cdn", "example.com"}, nil)
				r.MOQT.Proof = p
				return r
			}, cat.ErrProof},
		{"actx with a key it does not define", func(d *dpopCase) { actx(d)[4] = 1 }, nil, cat.ErrProof},
		{"a token without cnf ignores the proof", func(d *dpopCase) { d.cnf = nil; d.claims[6] = 0 }, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDPoPCase(t)
			tc.change(d)
			var token string
			if d.cnf == nil {
				token = claimsToken(t, map[any]any{moqtKey: map[any]any{0: []any{[]any{[]any{1, 4, 7}}}}})
			} else {
				token = d.token(t)
			}
			req := sportsRequest
			if tc.req != nil {
				req = tc.req
			}
			_, err := dpopValidator().ValidateRequest(token, req(d.proof(t, token)))
			if tc.want == nil && err != nil {
				t.Fatalf("ValidateRequest: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMOQTDPoPNeedsItsClaimKeys(t *testing.T) {
	d := newDPoPCase(t)
	token := d.token(t)
	for _, v := range []*cat.Validator{validator(), func() *cat.Validator { v := dpopValidator(); v.AthKey = 0; return v }(),
		func() *cat.Validator { v := dpopValidator(); v.ActxKey = 0; return v }()} {
		if _, err := v.ValidateRequest(token, sportsRequest(d.proof(t, token))); !errors.Is(err, cwt.ErrUnsupported) {
			t.Fatalf("got %v, want unsupported while actx or ath has no key", err)
		}
	}
}

// TestCKTOverHTTP checks that a token bound only by ckt cannot be used over HTTP, whose proofs are checked by jkt, and
// that Validate, which has no request, refuses it.
func TestCKTOverHTTP(t *testing.T) {
	d := newDPoPCase(t)
	token := d.token(t)
	_, err := dpopValidator().ValidateRequest(token, get())
	wantKind(t, err, cat.ErrProof)
	_, err = dpopValidator().Validate(token)
	if !errors.Is(err, cwt.ErrUnsupported) {
		t.Fatalf("Validate: got %v, want unsupported", err)
	}
}

func TestCKTSyntax(t *testing.T) {
	for name, cnf := range map[string]map[int64]any{
		"ckt of 31 bytes": {5: make([]byte, 31)},
		"ckt as text":     {5: "thumbprint"},
		"jkt of 33 bytes": {5: make([]byte, 32), 323: make([]byte, 33)},
		"ckt tagged":      {5: cbor.Tag{Number: 24, Content: make([]byte, 32)}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := dpopValidator().ValidateRequest(claimsToken(t, map[any]any{8: cnf}), sportsRequest(nil))
			if !errors.Is(err, cwt.ErrMalformed) {
				t.Fatalf("got %v, want malformed", err)
			}
		})
	}
}

// TestMOQTProofReplay checks decision 0038's replay detection: asked for by catdpop's jti setting, with until the
// proof's iat plus the window, and called only once every other check has passed.
func TestMOQTProofReplay(t *testing.T) {
	seen := map[string]bool{}
	var calls int
	var until time.Time
	v := dpopValidator()
	v.ProofReplay = func(cti []byte, u time.Time) bool {
		calls++
		until = u
		was := seen[string(cti)]
		seen[string(cti)] = true
		return was
	}
	d := newDPoPCase(t)
	d.extra = map[any]any{321: map[any]any{0: 120, 1: 1}}
	d.claims[6] = testNow.Unix() + 30
	token := d.token(t)
	proof := d.proof(t, token)
	if _, err := v.ValidateRequest(token, sportsRequest(proof)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if want := testNow.Add(150 * time.Second); !until.Equal(want) {
		t.Errorf("until = %v, want iat + window = %v", until, want)
	}
	_, err := v.ValidateRequest(token, sportsRequest(proof))
	wantKind(t, err, cat.ErrProof)

	// A request refused for its action never uses up a proof.
	calls = 0
	refused := sportsRequest(proof)
	refused.MOQT.Action = 6
	if _, err := v.ValidateRequest(token, refused); err == nil {
		t.Fatal("action 6 was accepted")
	}
	if calls != 0 {
		t.Errorf("ProofReplay called %d times for a refused request", calls)
	}

	// catdpop's jti setting 0, or none, asks for no detection.
	for _, setting := range []map[any]any{{0: 120, 1: 0}, {0: 120}} {
		calls = 0
		d.extra = map[any]any{321: setting}
		token := d.token(t)
		if _, err := v.ValidateRequest(token, sportsRequest(d.proof(t, token))); err != nil {
			t.Fatalf("catdpop %v: %v", setting, err)
		}
		if calls != 0 {
			t.Errorf("catdpop %v: ProofReplay called %d times", setting, calls)
		}
	}
}
