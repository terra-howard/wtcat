package cwt

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/fxamacker/cbor/v2"
)

// Tags and labels for messages with several signers or recipients (RFC 9052 Sections 4.1 and 6.1; decision 0029).
const (
	tagMac  = 97
	tagSign = 98

	algDirect = -6 // the direct key method for a COSE_Mac recipient (RFC 9052 Section 8.5.1)
)

// party is one signer of a COSE_Sign or one recipient of a COSE_Mac.
type party struct {
	protectedRaw []byte
	alg          Algorithm
	hasAlg       bool
	kid          []byte
	sig          []byte // the signature; empty for a recipient
}

// multiMessage is a parsed COSE_Sign or COSE_Mac message.
type multiMessage struct {
	coseTag      uint64 // tagSign or tagMac
	protectedRaw []byte // the body's protected header exactly as received
	alg          Algorithm
	hasAlg       bool // a COSE_Mac's MAC algorithm, if its body names one
	payload      []byte
	macTag       []byte // a COSE_Mac's tag
	parties      []party
}

// coseTagOf returns the COSE tag of a token, looking through a CWT tag, or 0 if it has none. It does not report
// errors; the parser that follows does.
func coseTagOf(token []byte) uint64 {
	var rt cbor.RawTag
	if len(token) == 0 || majorType(token) != majorTag || decMode.Unmarshal(token, &rt) != nil {
		return 0
	}
	if rt.Number == tagCWT {
		inner := []byte(rt.Content)
		if len(inner) == 0 || majorType(inner) != majorTag || decMode.Unmarshal(inner, &rt) != nil {
			return 0
		}
	}
	return rt.Number
}

// parseMulti parses a tagged COSE_Sign or COSE_Mac message under decision 0029's header rules. It does not verify
// anything.
func parseMulti(token []byte) (*multiMessage, error) {
	var rt cbor.RawTag
	if err := decMode.Unmarshal(token, &rt); err != nil {
		return nil, malformed("token: %v", err)
	}
	if rt.Number == tagCWT {
		if err := decMode.Unmarshal(rt.Content, &rt); err != nil {
			return nil, malformed("tag: %v", err)
		}
	}
	msg := &multiMessage{coseTag: rt.Number}
	want := 4
	if rt.Number == tagMac {
		want = 5
	}
	var parts []cbor.RawMessage
	if err := decMode.Unmarshal(rt.Content, &parts); err != nil {
		return nil, malformed("not a COSE array: %v", err)
	}
	if len(parts) != want {
		return nil, malformed("COSE array has %d elements, want %d", len(parts), want)
	}
	for i, p := range parts {
		if len(p) == 0 {
			return nil, malformed("COSE element %d is empty", i)
		}
	}

	protected, unprotected, err := headersOf(parts[0], parts[1], &msg.protectedRaw)
	if err != nil {
		return nil, err
	}
	alg, hasAlg, kid, err := checkHeaders(protected, unprotected)
	if err != nil {
		return nil, err
	}
	if kid != nil {
		return nil, malformed("kid belongs in each signer's or recipient's header, not the body's")
	}
	if hasAlg && rt.Number == tagSign {
		return nil, malformed("a COSE_Sign's algorithms belong in each signer's header, not the body's")
	}
	msg.alg, msg.hasAlg = alg, hasAlg

	switch {
	case parts[2][0] == 0xf6:
		return nil, unsupported("detached payload")
	case majorType(parts[2]) != majorBytes:
		return nil, malformed("payload is not a byte string")
	}
	if err := decMode.Unmarshal(parts[2], &msg.payload); err != nil {
		return nil, malformed("payload: %v", err)
	}

	list := parts[3]
	if rt.Number == tagMac {
		if majorType(parts[3]) != majorBytes {
			return nil, malformed("MAC tag is not a byte string")
		}
		if err := decMode.Unmarshal(parts[3], &msg.macTag); err != nil {
			return nil, malformed("MAC tag: %v", err)
		}
		list = parts[4]
	}
	var items []cbor.RawMessage
	if majorType(list) != majorArray {
		return nil, malformed("the signers or recipients are not an array")
	}
	if err := decMode.Unmarshal(list, &items); err != nil {
		return nil, malformed("signers or recipients: %v", err)
	}
	if len(items) == 0 {
		return nil, malformed("no signers or recipients")
	}
	for _, item := range items {
		p, err := parseParty(item, rt.Number == tagMac)
		if err != nil {
			return nil, err
		}
		msg.parties = append(msg.parties, p)
	}
	return msg, nil
}

// headersOf decodes a protected header (a byte string holding a map, kept raw in *protectedRaw) and an unprotected
// header (a map).
func headersOf(protectedItem, unprotectedItem cbor.RawMessage, protectedRaw *[]byte) (protected, unprotected map[int64]cbor.RawMessage, err error) {
	if majorType(protectedItem) != majorBytes {
		return nil, nil, malformed("protected header is not a byte string")
	}
	if err := decMode.Unmarshal(protectedItem, protectedRaw); err != nil {
		return nil, nil, malformed("protected header: %v", err)
	}
	if protected, err = decodeHeader(*protectedRaw, true); err != nil {
		return nil, nil, err
	}
	if majorType(unprotectedItem) != majorMap {
		return nil, nil, malformed("unprotected header is not a map")
	}
	if unprotected, err = decodeHeader(unprotectedItem, false); err != nil {
		return nil, nil, err
	}
	return protected, unprotected, nil
}

// parseParty parses one COSE_Signature ([protected, unprotected, signature]) or one COSE_recipient using the direct
// method ([protected, unprotected, empty ciphertext]).
func parseParty(item cbor.RawMessage, recipient bool) (party, error) {
	var p party
	var parts []cbor.RawMessage
	if majorType(item) != majorArray {
		return p, malformed("a signer or recipient is not an array")
	}
	if err := decMode.Unmarshal(item, &parts); err != nil {
		return p, malformed("signer or recipient: %v", err)
	}
	if recipient && len(parts) == 4 {
		return p, unsupported("a recipient with recipients of its own")
	}
	if len(parts) != 3 {
		return p, malformed("a signer or recipient has %d elements, want 3", len(parts))
	}
	for i, x := range parts {
		if len(x) == 0 {
			return p, malformed("signer or recipient element %d is empty", i)
		}
	}
	protected, unprotected, err := headersOf(parts[0], parts[1], &p.protectedRaw)
	if err != nil {
		return p, err
	}
	if majorType(parts[2]) != majorBytes {
		return p, malformed("a signature or recipient ciphertext is not a byte string")
	}
	if err := decMode.Unmarshal(parts[2], &p.sig); err != nil {
		return p, malformed("signature: %v", err)
	}
	if !recipient {
		p.alg, p.hasAlg, p.kid, err = checkHeaders(protected, unprotected)
		return p, err
	}
	return p, checkRecipient(&p, protected, unprotected)
}

// checkRecipient applies decision 0029 to a COSE_Mac recipient: the direct method only, which RFC 9052 Section
// 8.5.1 gives an empty protected header and an empty ciphertext, with alg and kid as the only parameters.
func checkRecipient(p *party, protected, unprotected map[int64]cbor.RawMessage) error {
	if len(protected) != 0 {
		return malformed("a direct recipient's protected header must be empty")
	}
	if len(p.sig) != 0 {
		return malformed("a direct recipient's ciphertext must be empty")
	}
	for label := range unprotected {
		if label != labelAlg && label != labelKID {
			return unsupported("recipient header parameter %d is not understood", label)
		}
	}
	rawAlg, ok := unprotected[labelAlg]
	if !ok {
		return malformed("a recipient has no alg")
	}
	var id int64
	if decMode.Unmarshal(rawAlg, &id) != nil {
		return unsupported("a recipient alg that is not an integer")
	}
	if id != algDirect {
		return unsupported("recipient algorithm %d; only the direct method (-6) is supported", id)
	}
	if rawKID, ok := unprotected[labelKID]; ok {
		kid, err := decodeKID(rawKID)
		if err != nil {
			return err
		}
		p.kid = kid
	}
	return nil
}

// verifyMulti verifies a COSE_Sign or COSE_Mac under decision 0029's policy: a party whose kid the lookup does not
// know is skipped, a party whose key is known must verify, and at least one must verify.
func verifyMulti(token []byte, lookup KeyLookup) (*Message, error) {
	msg, err := parseMulti(token)
	if err != nil {
		return nil, err
	}
	var verified *Message
	for _, p := range msg.parties {
		key, err := lookup(p.kid)
		if err != nil {
			continue // a signer or recipient this recipient does not know
		}
		if !key.Algorithm.known() {
			return nil, unsupported("key for %v", key.Algorithm)
		}
		if err := verifyParty(msg, p, key); err != nil {
			return nil, err
		}
		if verified == nil {
			verified = &Message{Algorithm: key.Algorithm, KID: p.kid, Protected: msg.protectedRaw, Payload: msg.payload}
		}
	}
	if verified == nil {
		return nil, unverified("no signer or recipient has a key this recipient knows")
	}
	return verified, nil
}

// verifyParty checks one signer's signature, or the MAC for one recipient's key.
func verifyParty(msg *multiMessage, p party, key Key) error {
	if msg.coseTag == tagSign {
		if key.Algorithm.isMAC() {
			return malformed("COSE tag %d does not match %v", msg.coseTag, key.Algorithm)
		}
		if p.hasAlg && !p.alg.known() {
			return unsupported("%v", p.alg)
		}
		if p.hasAlg && p.alg != key.Algorithm {
			return unverified("the signer's alg is %v but its key is for %v", p.alg, key.Algorithm)
		}
		toBeSigned, err := cbor.Marshal([]any{"Signature", nonNil(msg.protectedRaw), nonNil(p.protectedRaw), []byte{}, nonNil(msg.payload)})
		if err != nil {
			return malformed("building signature structure: %v", err)
		}
		switch key.Algorithm {
		case ES256:
			return verifyES256(key.Material, toBeSigned, p.sig)
		default:
			return verifyPS256(key.Material, toBeSigned, p.sig)
		}
	}
	if !key.Algorithm.isMAC() {
		return malformed("COSE tag %d does not match %v", msg.coseTag, key.Algorithm)
	}
	if msg.hasAlg && !msg.alg.known() {
		return unsupported("%v", msg.alg)
	}
	if msg.hasAlg && msg.alg != key.Algorithm {
		return unverified("the message's alg is %v but its key is for %v", msg.alg, key.Algorithm)
	}
	secret, ok := key.Material.([]byte)
	if !ok {
		return unverified("%v needs a []byte key, got %T", key.Algorithm, key.Material)
	}
	if len(secret) == 0 {
		return unverified("empty key")
	}
	toMac, err := cbor.Marshal([]any{"MAC", nonNil(msg.protectedRaw), []byte{}, nonNil(msg.payload)})
	if err != nil {
		return malformed("building MAC structure: %v", err)
	}
	tagLen := 32
	if key.Algorithm == HMAC256x64 {
		tagLen = 8
	}
	h := hmac.New(sha256.New, secret)
	h.Write(toMac)
	if len(msg.macTag) != tagLen || !hmac.Equal(msg.macTag, h.Sum(nil)[:tagLen]) {
		return ErrVerification
	}
	return nil
}
