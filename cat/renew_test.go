package cat_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

var renewKey = []byte("renewal key, thirty-two bytes!!!")

// renewer is a Validator that accepts tokens from "issuer" (key k1) and from itself, "cdn" (key r1), and renews
// with r1.
func renewer() *cat.Validator {
	v := validator()
	v.Keys = func(kid []byte) (cat.Key, error) {
		if string(kid) == "r1" {
			return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: renewKey}, Issuer: "cdn"}, nil
		}
		return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: hmacSecret}, Issuer: "issuer"}, nil
	}
	v.Issuance = &cat.Issuance{Issuer: "cdn", Key: func(kid string) (cwt.SigningKey, error) {
		if kid != "" {
			return cwt.SigningKey{}, errors.New("no such key")
		}
		return cwt.SigningKey{Algorithm: cwt.HMAC256x256, KID: []byte("r1"), Material: renewKey}, nil
	}}
	return v
}

// renewed validates text, renews it, and decodes the new token's claims as raw values.
func renewed(t *testing.T, v *cat.Validator, text string) (*cat.Renewal, map[int64]cbor.RawMessage) {
	t.Helper()
	tok, err := v.Validate(text)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	r, err := v.Renew(tok, testNow)
	if err != nil || r == nil {
		t.Fatalf("Renew = %v, %v; want a renewal", r, err)
	}
	if _, err := v.Validate(r.Token); err != nil {
		t.Fatalf("the renewed token does not validate: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(r.Token)
	msg, err := cwt.VerifyMessage(raw, func([]byte) (cwt.Key, error) {
		return cwt.Key{Algorithm: cwt.HMAC256x256, Material: renewKey}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var claims map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(msg.Payload, &claims); err != nil {
		t.Fatal(err)
	}
	return r, claims
}

func TestRenewCookie(t *testing.T) {
	geo := []string{"CA"}
	text := claimsToken(t, map[any]any{
		1: "issuer", 4: testNow.Unix() + 10, 6: testNow.Unix() - 100, 7: []byte{1, 2, 3}, 999: "kept", 316: geo,
		323: map[int64]any{0: 1, 1: 60, 3: "CAT2", 5: []string{"Secure", "HttpOnly"}},
	})
	r, claims := renewed(t, renewer(), text)
	if r.Type != cat.RenewCookie || r.CookieName != "CAT2" || len(r.CookieParams) != 2 || r.CookieParams[1] != "HttpOnly" {
		t.Errorf("renewal = %+v", r)
	}
	if !bytes.Equal(claims[4], enc(t, testNow.Unix()+60)) || !bytes.Equal(claims[6], enc(t, testNow.Unix())) || !bytes.Equal(claims[1], enc(t, "cdn")) {
		t.Errorf("exp, iat, iss = %x, %x, %x", claims[4], claims[6], claims[1])
	}
	var cti []byte
	if err := cbor.Unmarshal(claims[7], &cti); err != nil || len(cti) != 16 || bytes.Equal(cti, []byte{1, 2, 3}) {
		t.Errorf("cti = %x, want 16 fresh bytes", cti)
	}
	for key, want := range map[int64][]byte{999: enc(t, "kept"), 316: enc(t, geo)} {
		if !bytes.Equal(claims[key], want) {
			t.Errorf("claim %d = %x, want it unchanged, %x", key, claims[key], want)
		}
	}
	if len(claims[323]) == 0 {
		t.Error("catr itself was not carried over")
	}
}

func TestRenewKeepsAnAbsentCtiAbsent(t *testing.T) {
	_, claims := renewed(t, renewer(), claimsToken(t, map[any]any{323: map[int64]any{0: 2, 1: 30, 4: "X-Token"}}))
	if _, ok := claims[7]; ok {
		t.Error("the renewed token has a cti, but the received one had none")
	}
}

func TestRenewFractionalExpadd(t *testing.T) {
	_, claims := renewed(t, renewer(), claimsToken(t, map[any]any{323: map[int64]any{0: 3, 1: 0.5}}))
	if !bytes.Equal(claims[4], enc(t, float64(testNow.Unix())+0.5)) {
		t.Errorf("exp = %x, want now + 0.5 as a float", claims[4])
	}
}

func TestRenewShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		catr map[int64]any
		want cat.RenewalType
	}{
		{"automatic, with a name", map[int64]any{0: 0, 1: 60, 3: "c"}, cat.RenewAutomatic},
		{"header", map[int64]any{0: 2, 1: 60, 4: "X-Token", 6: []string{"a=1"}}, cat.RenewHeader},
		{"redirect, with a status", map[int64]any{0: 3, 1: 60, 7: 302}, cat.RenewRedirect},
	} {
		r, _ := renewed(t, renewer(), claimsToken(t, map[any]any{323: tc.catr}))
		if r.Type != tc.want {
			t.Errorf("%s: type %d, want %d", tc.name, r.Type, tc.want)
		}
	}
	r, _ := renewed(t, renewer(), claimsToken(t, map[any]any{323: map[int64]any{0: 3, 1: 60}}))
	if r.Status != 307 {
		t.Errorf("redirect status %d, want 307 by default", r.Status)
	}
}

func TestRenewDeadline(t *testing.T) {
	v := renewer()
	early := claimsToken(t, map[any]any{4: testNow.Unix() + 100, 323: map[int64]any{0: 1, 1: 60, 2: 30}})
	tok, err := v.Validate(early)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := v.Renew(tok, testNow); r != nil || err != nil {
		t.Errorf("before the deadline: Renew = %v, %v; want nothing", r, err)
	}
	if r, err := v.Renew(tok, testNow.Add(75*time.Second)); r == nil || err != nil {
		t.Errorf("inside the deadline: Renew = %v, %v; want a renewal", r, err)
	}
}

func TestRenewDoesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		v    *cat.Validator
		text string
	}{
		"without Issuance": {validator(), claimsToken(t, map[any]any{323: map[int64]any{0: 1, 1: 60}})},
		"without catr":     {renewer(), claimsToken(t, map[any]any{})},
		"an unknown type":  {renewer(), claimsToken(t, map[any]any{323: map[int64]any{0: 9, 1: 60}})},
	} {
		tok, err := tc.v.Validate(tc.text)
		if err != nil {
			t.Fatal(err)
		}
		if r, err := tc.v.Renew(tok, testNow); r != nil || err != nil {
			t.Errorf("%s: Renew = %v, %v; want nothing and no error", name, r, err)
		}
	}
}

// A catr the recipient cannot follow means no renewal, never an invalid token (decision 0022).
func TestRenewRefuses(t *testing.T) {
	for name, catr := range map[string]any{
		"not a map":                    []any{},
		"no type":                      map[int64]any{1: 60},
		"no expadd":                    map[int64]any{0: 1},
		"expadd text":                  map[int64]any{0: 1, 1: "60"},
		"cookie with a header name":    map[int64]any{0: 1, 1: 60, 4: "X"},
		"header with a cookie name":    map[int64]any{0: 2, 1: 60, 3: "c"},
		"redirect with cookie params":  map[int64]any{0: 3, 1: 60, 5: []string{"Secure"}},
		"automatic with header params": map[int64]any{0: 0, 1: 60, 6: []string{"a"}},
		"a redirect status of 200":     map[int64]any{0: 3, 1: 60, 7: 200},
		"an unknown parameter":         map[int64]any{0: 1, 1: 60, 9: 1},
		"a deadline without exp":       map[int64]any{0: 1, 1: 60, 2: 30},
		"cookie params not strings":    map[int64]any{0: 1, 1: 60, 5: []any{1}},
	} {
		v := renewer()
		tok, err := v.Validate(claimsToken(t, map[any]any{323: catr}))
		if err != nil {
			t.Fatalf("%s: the token itself must stay valid: %v", name, err)
		}
		if r, err := v.Renew(tok, testNow); r != nil || !errors.Is(err, cat.ErrNoRenewal) {
			t.Errorf("%s: Renew = %v, %v; want cat.ErrNoRenewal", name, r, err)
		}
	}
}

// With no issuer name, the renewed token carries no iss: keeping the old one would name the wrong issuer.
func TestRenewWithoutAnIssuerNameDropsIss(t *testing.T) {
	v := renewer()
	v.Issuance.Issuer = ""
	v.Keys = func([]byte) (cat.Key, error) {
		return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: renewKey}, Issuer: "someone"}, nil
	}
	text := base64.RawURLEncoding.EncodeToString(func() []byte {
		raw, err := cwt.Issue(enc(t, map[any]any{1: "someone", 323: map[int64]any{0: 1, 1: 60}}), cwt.SigningKey{Algorithm: cwt.HMAC256x256, Material: renewKey})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}())
	_, claims := renewed(t, v, text)
	if _, ok := claims[1]; ok {
		t.Error("the renewed token kept an iss")
	}
}
