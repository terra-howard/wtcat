package cat

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// proof is a DPoP proof (RFC 9449) whose signature verified with the key in its own header (decision 0020).
type proof struct {
	jkt                []byte // the RFC 7638 thumbprint of the proof's key
	jti, htm, htu, ath string
	hasAth             bool
	iat                float64
}

// privateMembers are JWK members that would carry a private key (RFC 7518 Section 6).
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// parseProof parses a compact JWS DPoP proof, verifies its signature with the jwk in its header, and computes that
// key's thumbprint. JSON members are read by their exact names: encoding/json would match struct fields ignoring
// case.
func parseProof(compact string) (*proof, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS of three parts")
	}
	var raw [3][]byte
	for i, part := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil {
			return nil, fmt.Errorf("part %d is not unpadded base64url: %v", i+1, err)
		}
		raw[i] = b
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(raw[0], &header); err != nil || header == nil {
		return nil, errors.New("the header is not a JSON object")
	}
	if _, ok := header["crit"]; ok {
		return nil, errors.New("a crit header parameter, which this verifier does not understand")
	}
	typ, err := jsonString(header, "typ")
	if err != nil || !strings.EqualFold(typ, "dpop+jwt") {
		return nil, errors.New("typ is not dpop+jwt")
	}
	alg, err := jsonString(header, "alg")
	if err != nil {
		return nil, err
	}
	var jwk map[string]json.RawMessage
	if err := json.Unmarshal(header["jwk"], &jwk); err != nil || jwk == nil {
		return nil, errors.New("jwk is not a JSON object")
	}
	key, err := publicKey(jwk, alg)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := verifySignature(key, digest[:], raw[2]); err != nil {
		return nil, err
	}
	jkt, err := thumbprint(jwk)
	if err != nil {
		return nil, err
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw[1], &payload); err != nil || payload == nil {
		return nil, errors.New("the payload is not a JSON object")
	}
	p := &proof{jkt: jkt}
	for name, dst := range map[string]*string{"jti": &p.jti, "htm": &p.htm, "htu": &p.htu} {
		if *dst, err = jsonString(payload, name); err != nil {
			return nil, err
		}
	}
	if p.jti == "" {
		return nil, errors.New("jti is empty")
	}
	if err := json.Unmarshal(payload["iat"], &p.iat); err != nil || payload["iat"] == nil || math.IsInf(p.iat, 0) {
		return nil, errors.New("iat is not a number")
	}
	if _, ok := payload["ath"]; ok {
		if p.ath, err = jsonString(payload, "ath"); err != nil {
			return nil, err
		}
		p.hasAth = true
	}
	return p, nil
}

// jsonString reads a member that must be a JSON string.
func jsonString(obj map[string]json.RawMessage, name string) (string, error) {
	v, ok := obj[name]
	var s string
	if !ok || len(v) == 0 || v[0] != '"' || json.Unmarshal(v, &s) != nil {
		return "", fmt.Errorf("%s is missing or not a string", name)
	}
	return s, nil
}

// publicKey reads a public EC P-256 key for ES256 or a public RSA key of at least 2048 bits for PS256.
func publicKey(jwk map[string]json.RawMessage, alg string) (crypto.PublicKey, error) {
	for _, m := range privateMembers {
		if _, ok := jwk[m]; ok {
			return nil, errors.New("jwk carries a private key")
		}
	}
	kty, err := jsonString(jwk, "kty")
	if err != nil {
		return nil, err
	}
	member := func(name string) ([]byte, error) {
		s, err := jsonString(jwk, name)
		if err != nil {
			return nil, err
		}
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("jwk member %s is not base64url", name)
		}
		return b, nil
	}
	switch {
	case alg == "ES256" && kty == "EC":
		crv, err := jsonString(jwk, "crv")
		if err != nil || crv != "P-256" {
			return nil, errors.New("ES256 needs a P-256 key")
		}
		x, err := member("x")
		if err != nil {
			return nil, err
		}
		y, err := member("y")
		if err != nil {
			return nil, err
		}
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("a P-256 coordinate is not 32 bytes")
		}
		return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	case alg == "PS256" && kty == "RSA":
		n, err := member("n")
		if err != nil {
			return nil, err
		}
		e, err := member("e")
		if err != nil {
			return nil, err
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 || len(e) > 4 || pub.E < 3 {
			return nil, errors.New("the RSA key is below 2048 bits or has an unusable exponent")
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("alg %q with a %q key is not accepted", alg, kty)
	}
}

func verifySignature(key crypto.PublicKey, digest, sig []byte) error {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if len(sig) != 64 || !ecdsa.Verify(k, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("the ES256 signature does not verify")
		}
	case *rsa.PublicKey:
		if rsa.VerifyPSS(k, crypto.SHA256, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) != nil {
			return errors.New("the PS256 signature does not verify")
		}
	}
	return nil
}

// thumbprint computes a JWK's SHA-256 thumbprint (RFC 7638): the required members, in lexicographic order, as
// compact JSON.
func thumbprint(jwk map[string]json.RawMessage) ([]byte, error) {
	kty, err := jsonString(jwk, "kty")
	if err != nil {
		return nil, err
	}
	var names []string
	switch kty {
	case "EC":
		names = []string{"crv", "kty", "x", "y"}
	case "RSA":
		names = []string{"e", "kty", "n"}
	default:
		return nil, fmt.Errorf("no thumbprint for kty %q", kty)
	}
	var b bytes.Buffer
	b.WriteByte('{')
	for i, name := range names {
		v, err := jsonString(jwk, name)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			b.WriteByte(',')
		}
		enc, _ := json.Marshal(v)
		fmt.Fprintf(&b, "%q:%s", name, enc)
	}
	b.WriteByte('}')
	sum := sha256.Sum256(b.Bytes())
	return sum[:], nil
}
