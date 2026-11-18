package cat

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	var alg int64
	if a, ok := header[headerAlg]; !ok || decMode.Unmarshal(a, &alg) != nil || alg != int64(cwt.ES256) {
		return nil, errors.New("the proof's alg is not ES256, the one algorithm supported for MOQT proofs")
	}
	var typ string
	if t, ok := header[headerTyp]; !ok || majorType(t) != majorText || decMode.Unmarshal(t, &typ) != nil || typ != moqtProofTyp {
		return nil, fmt.Errorf("the proof's typ is not %q", moqtProofTyp)
	}
	key, err := kccsKey(header[headerKCCS])
	if err != nil {
		return nil, err
	}
	toBeSigned, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(toBeSigned)
	if err := verifySignature(key, digest[:], sig); err != nil {
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

// kccsKey reads the public key from a kccs header parameter: a CWT Claims Set whose cnf holds a COSE_Key, which must
// be an EC2 key on P-256.
func kccsKey(kccs cbor.RawMessage) (*ecdsa.PublicKey, error) {
	var claims, cnf, key map[int64]cbor.RawMessage
	if kccs == nil || decMode.Unmarshal(kccs, &claims) != nil {
		return nil, errors.New("the proof has no kccs in its protected header")
	}
	if decMode.Unmarshal(claims[claimCnf], &cnf) != nil || decMode.Unmarshal(cnf[1], &key) != nil {
		return nil, errors.New("the proof's kccs has no cnf COSE_Key")
	}
	if _, ok := key[-4]; ok {
		return nil, errors.New("the proof's COSE_Key carries a private key")
	}
	var kty, crv int64
	if decMode.Unmarshal(key[1], &kty) != nil || kty != 2 || decMode.Unmarshal(key[-1], &crv) != nil || crv != 1 {
		return nil, errors.New("the proof's COSE_Key is not an EC2 key on P-256")
	}
	// A y that is not a byte string, such as the sign bit of a compressed point, decodes to nothing, and then the
	// point has the wrong length, as it does when x has 32 bytes and y does not.
	x, _ := proofBytes(key[-2])
	y, _ := proofBytes(key[-3])
	if len(x) != 32 {
		return nil, errors.New("the proof's COSE_Key does not hold a 32-byte x")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, errors.New("the proof's COSE_Key is not a point on P-256")
	}
	return pub, nil
}

// coseThumbprints returns a P-256 key's COSE Key Thumbprint (RFC 9679), the SHA-256 of the deterministic encoding of
// kty, crv, x and y, and the JWK SHA-256 Thumbprint (RFC 7638) of the equivalent JWK.
func coseThumbprints(pub *ecdsa.PublicKey) (ckt, jkt []byte, err error) {
	pt, err := pub.Bytes()
	if err != nil {
		return nil, nil, err
	}
	x, y := pt[1:33], pt[33:]
	var b bytes.Buffer
	b.Write([]byte{0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20}) // {1: 2, -1: 1, -2: h'...
	b.Write(x)
	b.Write([]byte{0x22, 0x58, 0x20}) // -3: h'...
	b.Write(y)
	sum := sha256.Sum256(b.Bytes())
	str := func(s string) json.RawMessage { m, _ := json.Marshal(s); return m }
	jkt, err = thumbprint(map[string]json.RawMessage{
		"kty": str("EC"), "crv": str("P-256"),
		"x": str(base64.RawURLEncoding.EncodeToString(x)), "y": str(base64.RawURLEncoding.EncodeToString(y)),
	})
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
