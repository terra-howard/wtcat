package cat

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

// MOQT DPoP proofs (draft-ietf-moq-c4m section "DPoP for MOQT", decision 0038).

const (
	moqtProofTyp = "dpop-proof+cwt"
	headerAlg    = 1
	headerKCCS   = 14 // RFC 9528
	headerTyp    = 16
)

// moqtProof is what a MOQT DPoP proof says, once its signature has been verified with the key it carries.
type moqtProof struct {
	ckt, jkt []byte // the two thumbprints of the proof's key
	cti      []byte
	iat      int64
	ath      []byte
	actx     map[int64]cbor.RawMessage
}

// checkMOQTProof checks the DPoP proof of a MOQT request against the token's cnf. When catdpop asks for replay
// detection it returns the proof's cti and the time until which it must be remembered, for ProofReplay, which the
// caller calls once every other check has passed.
func (v *Validator) checkMOQTProof(c *Claims, req *Request, token string, now time.Time) (cti []byte, until time.Time, err error) {
	if c.jkt == nil && c.ckt == nil {
		return nil, time.Time{}, nil
	}
	if v.ActxKey == 0 || v.AthKey == 0 {
		return nil, time.Time{}, unsupported("a MOQT DPoP proof needs Validator.ActxKey and Validator.AthKey, which have no assigned values yet (decision 0038)")
	}
	if len(req.MOQT.Proof) == 0 {
		return nil, time.Time{}, fmt.Errorf("%w: the token has cnf and the MOQT action carries no proof", ErrProof)
	}
	p, err := parseMOQTProof(req.MOQT.Proof, v.ActxKey, v.AthKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%w: %v", ErrProof, err)
	}
	if c.ckt != nil && !bytes.Equal(p.ckt, c.ckt) || c.jkt != nil && !bytes.Equal(p.jkt, c.jkt) {
		return nil, time.Time{}, fmt.Errorf("%w: the key of the proof is not the one cnf names", ErrProof)
	}
	raw, err := decodeText(token, len(token))
	if err != nil {
		return nil, time.Time{}, err
	}
	if sum := sha256.Sum256(raw); !bytes.Equal(p.ath, sum[:]) {
		return nil, time.Time{}, fmt.Errorf("%w: ath does not match the token", ErrProof)
	}
	window := v.dpopWindow(c)
	issued := time.Unix(p.iat, 0)
	if age := now.Sub(issued); age > window || age < -window {
		return nil, time.Time{}, fmt.Errorf("%w: iat is outside the %v window", ErrProof, window)
	}
	if err := checkActx(p.actx, req.MOQT); err != nil {
		return nil, time.Time{}, fmt.Errorf("%w: %v", ErrProof, err)
	}
	if !c.dpopJTI {
		return nil, time.Time{}, nil
	}
	return p.cti, issued.Add(window), nil
}

// parseMOQTProof parses a COSE_Sign1 proof, tagged or not, and verifies its signature with the key in its kccs.
func parseMOQTProof(raw []byte, actxKey, athKey int64) (*moqtProof, error) {
	body := cbor.RawMessage(raw)
	if majorType(raw) == majorTag {
		var tag cbor.RawTag
		if decMode.Unmarshal(raw, &tag) != nil || tag.Number != 18 {
			return nil, errors.New("the proof is not a COSE_Sign1")
		}
		body = tag.Content
	}
	var parts []cbor.RawMessage
	if majorType(body) != majorArray || decMode.Unmarshal(body, &parts) != nil || len(parts) != 4 {
		return nil, errors.New("the proof is not a COSE_Sign1")
	}
	protected, err := proofBytes(parts[0])
	if err != nil {
		return nil, errors.New("the proof's protected header is not in a byte string")
	}
	if majorType(parts[1]) != majorMap {
		return nil, errors.New("the proof's unprotected header is not a map")
	}
	payload, err := proofBytes(parts[2])
	if err != nil {
		return nil, errors.New("the proof's payload is not in a byte string")
	}
	sig, err := proofBytes(parts[3])
	if err != nil {
		return nil, errors.New("the proof's signature is not a byte string")
	}
	var header map[int64]cbor.RawMessage
	if decMode.Unmarshal(protected, &header) != nil {
		return nil, errors.New("the proof's protected header is not a map with integer labels")
	}
	var typ string
	if t, ok := header[headerTyp]; !ok || majorType(t) != majorText || decMode.Unmarshal(t, &typ) != nil || typ != moqtProofTyp {
		return nil, fmt.Errorf("the proof's typ is not %q", moqtProofTyp)
	}
	key, err := kccsKey(header[headerKCCS])
	if err != nil {
		return nil, err
	}
	// The alg must be the one that signs with the key's curve, which also refuses a symmetric or unknown alg.
	var alg int64
	if decMode.Unmarshal(header[headerAlg], &alg) != nil || alg != key.curve.alg {
		return nil, fmt.Errorf("the proof's alg is not %s, the algorithm of its %s key", key.curve.algName, key.curve.name)
	}
	toBeSigned, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return nil, err
	}
	if err := key.verify(toBeSigned, sig); err != nil {
		return nil, err
	}
	p := &moqtProof{}
	if p.ckt, p.jkt, err = coseThumbprints(key); err != nil {
		return nil, err
	}
	var claims map[int64]cbor.RawMessage
	if decMode.Unmarshal(payload, &claims) != nil {
		return nil, errors.New("the proof's claims are not a map with integer keys")
	}
	if p.cti, err = proofBytes(claims[claimCti]); err != nil || len(p.cti) == 0 {
		return nil, errors.New("the proof's cti is not a non-empty byte string")
	}
	iat, ok := claims[claimIat]
	if !ok || majorType(iat) > majorNegative || decMode.Unmarshal(iat, &p.iat) != nil {
		return nil, errors.New("the proof's iat is not an integer")
	}
	if p.ath, err = proofBytes(claims[athKey]); err != nil {
		return nil, errors.New("the proof's ath is not a byte string")
	}
	a, ok := claims[actxKey]
	if !ok || majorType(a) != majorMap || decMode.Unmarshal(a, &p.actx) != nil {
		return nil, errors.New("the proof's actx is not a map with integer keys")
	}
	return p, nil
}

// proofCurve is a COSE_Key type and curve a MOQT proof may use, with the one alg that signs with it (decision 0038).
type proofCurve struct {
	kty, crv int64
	size     int            // the length of a coordinate
	ec       elliptic.Curve // nil for Ed25519
	name     string         // the curve's JWK name
	alg      int64
	algName  string
}

var proofCurves = []proofCurve{
	{kty: 2, crv: 1, size: 32, ec: elliptic.P256(), name: "P-256", alg: int64(cwt.ES256), algName: "ES256"},
	{kty: 2, crv: 2, size: 48, ec: elliptic.P384(), name: "P-384", alg: -35, algName: "ES384"},
	{kty: 1, crv: 6, size: 32, name: "Ed25519", alg: -8, algName: "EdDSA"},
}

// proofKey is the public key of a MOQT proof, with the COSE_Key parameters its thumbprints are made of.
type proofKey struct {
	pub   crypto.PublicKey // *ecdsa.PublicKey or ed25519.PublicKey
	curve proofCurve
	x, y  []byte // y is nil for an Ed25519 key
}

// kccsKey reads the public key from a kccs header parameter: a CWT Claims Set whose cnf holds a COSE_Key, which must
// be an EC2 key on P-256 or P-384, or an OKP key on Ed25519.
func kccsKey(kccs cbor.RawMessage) (proofKey, error) {
	var claims, cnf, key map[int64]cbor.RawMessage
	if kccs == nil || decMode.Unmarshal(kccs, &claims) != nil {
		return proofKey{}, errors.New("the proof has no kccs in its protected header")
	}
	if decMode.Unmarshal(claims[claimCnf], &cnf) != nil || decMode.Unmarshal(cnf[1], &key) != nil {
		return proofKey{}, errors.New("the proof's kccs has no cnf COSE_Key")
	}
	if _, ok := key[-4]; ok {
		return proofKey{}, errors.New("the proof's COSE_Key carries a private key")
	}
	// A kty or crv that is missing or not an integer decodes as 0, which no curve has.
	var kty, crv int64
	_ = decMode.Unmarshal(key[1], &kty)
	_ = decMode.Unmarshal(key[-1], &crv)
	i := slices.IndexFunc(proofCurves, func(c proofCurve) bool { return c.kty == kty && c.crv == crv })
	if i < 0 {
		return proofKey{}, errors.New("the proof's COSE_Key is not a P-256, P-384 or Ed25519 key")
	}
	k := proofKey{curve: proofCurves[i]}
	// A y that is not a byte string, such as the sign bit of a compressed point, decodes to nothing, and then the
	// point has the wrong length, as it does when x has the right length and y does not.
	k.x, _ = proofBytes(key[-2])
	if len(k.x) != k.curve.size {
		return proofKey{}, fmt.Errorf("the proof's COSE_Key does not hold a %d-byte x", k.curve.size)
	}
	if k.curve.ec == nil {
		k.pub = ed25519.PublicKey(k.x)
		return k, nil
	}
	k.y, _ = proofBytes(key[-3])
	pub, err := ecdsa.ParseUncompressedPublicKey(k.curve.ec, append(append([]byte{4}, k.x...), k.y...))
	if err != nil {
		return proofKey{}, fmt.Errorf("the proof's COSE_Key is not a point on %s", k.curve.name)
	}
	k.pub = pub
	return k, nil
}

// verify checks a signature over toBeSigned with the key, by the alg of its curve.
func (k proofKey) verify(toBeSigned, sig []byte) error {
	pub, ok := k.pub.(*ecdsa.PublicKey)
	if !ok {
		if !ed25519.Verify(k.pub.(ed25519.PublicKey), toBeSigned, sig) {
			return errors.New("the EdDSA signature does not verify")
		}
		return nil
	}
	digest := sha256.Sum256(toBeSigned)
	d := digest[:]
	if k.curve.size == 48 {
		digest384 := sha512.Sum384(toBeSigned)
		d = digest384[:]
	}
	n := k.curve.size
	if len(sig) != 2*n || !ecdsa.Verify(pub, d, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])) {
		return fmt.Errorf("the %s signature does not verify", k.curve.algName)
	}
	return nil
}

// thumbprintMode encodes a COSE_Key's required parameters deterministically, for its COSE Key Thumbprint.
var thumbprintMode, _ = cbor.EncOptions{Sort: cbor.SortCoreDeterministic}.EncMode()

// coseThumbprints returns a key's COSE Key Thumbprint (RFC 9679), the SHA-256 of the deterministic encoding of its
// required parameters (kty, crv, x, and y for an EC2 key), and the JWK SHA-256 Thumbprint (RFC 7638) of the
// equivalent JWK (RFC 8037 for Ed25519).
func coseThumbprints(k proofKey) (ckt, jkt []byte, err error) {
	str := func(s string) json.RawMessage { m, _ := json.Marshal(s); return m }
	b64 := base64.RawURLEncoding.EncodeToString
	required := map[int64]any{1: k.curve.kty, -1: k.curve.crv, -2: k.x}
	jwk := map[string]json.RawMessage{"kty": str("OKP"), "crv": str(k.curve.name), "x": str(b64(k.x))}
	if k.curve.kty == 2 {
		required[-3] = k.y
		jwk["kty"], jwk["y"] = str("EC"), str(b64(k.y))
	}
	encoded, err := thumbprintMode.Marshal(required)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(encoded)
	jkt, err = thumbprint(jwk)
	return sum[:], jkt, err
}

// checkActx checks that a proof's actx names the request's MOQT action exactly.
func checkActx(actx map[int64]cbor.RawMessage, a *MOQTAction) error {
	for k := range actx {
		if k < 0 || k > 3 {
			return fmt.Errorf("actx has key %d, which it does not define", k)
		}
	}
	var typ string
	if t, ok := actx[0]; !ok || majorType(t) != majorText || decMode.Unmarshal(t, &typ) != nil || typ != "moqt" {
		return errors.New(`actx's type is not "moqt"`)
	}
	var action int64
	if v, ok := actx[1]; !ok || majorType(v) != majorUnsigned || decMode.Unmarshal(v, &action) != nil || action != int64(a.Action) {
		return errors.New("actx names another action")
	}
	var namespace []cbor.RawMessage
	if v, ok := actx[2]; ok && (majorType(v) != majorArray || decMode.Unmarshal(v, &namespace) != nil) {
		return errors.New("actx's namespace is not an array")
	}
	if len(namespace) != len(a.Namespace) {
		return errors.New("actx names another namespace")
	}
	for i, f := range namespace {
		if b, err := proofBytes(f); err != nil || !bytes.Equal(b, a.Namespace[i]) {
			return errors.New("actx names another namespace")
		}
	}
	track, hasTrack := actx[3]
	if hasTrack != (a.Track != nil) {
		return errors.New("actx names another track")
	}
	if hasTrack {
		if b, err := proofBytes(track); err != nil || !bytes.Equal(b, a.Track) {
			return errors.New("actx names another track")
		}
	}
	return nil
}

// proofBytes decodes an untagged CBOR byte string, or fails for anything else, including nothing.
func proofBytes(v cbor.RawMessage) ([]byte, error) {
	var b []byte
	if len(v) == 0 || majorType(v) != majorBytes || decMode.Unmarshal(v, &b) != nil {
		return nil, errors.New("not a byte string")
	}
	return b, nil
}
