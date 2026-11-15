package cat_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

var b64u = base64.RawURLEncoding

// refusal validates text with req, which must fail as unacceptable, and returns the Unacceptable error.
func refusal(t *testing.T, v *cat.Validator, text string, req *cat.Request) *cat.Unacceptable {
	t.Helper()
	_, err := v.ValidateRequest(text, req)
	var u *cat.Unacceptable
	if !errors.As(err, &u) {
		t.Fatalf("got %v, want a *cat.Unacceptable", err)
	}
	return u
}

func ifRequest() *cat.Request {
	req := get()
	req.URI = "https://cdn.example/a.ts"
	req.ReceivedURI = "https://cdn.example/a.ts?CAT=old"
	return req
}

// minting is a Validator that can sign catif tokens with kid "r1".
func minting() *cat.Validator {
	v := renewer()
	v.Issuance.Key = func(kid string) (cwt.SigningKey, error) {
		if kid != "r1" {
			return cwt.SigningKey{}, errors.New("no such key")
		}
		return cwt.SigningKey{Algorithm: cwt.HMAC256x256, KID: []byte("r1"), Material: renewKey}, nil
	}
	return v
}

// Like the specification's first catif example: an expired token answered with a redirect.
func TestCatifStatusAndHeader(t *testing.T) {
	text := claimsToken(t, map[any]any{4: testNow.Unix() - 1, 322: map[int64]any{4: []any{307, map[string]any{"Location": "http://auth.example/"}}}})
	u := refusal(t, validator(), text, ifRequest())
	if u.Claim != 4 || !errors.Is(u, cat.ErrExpired) || !errors.Is(u, cat.ErrUnacceptable) {
		t.Fatalf("Unacceptable = claim %d, %v", u.Claim, u)
	}
	resp := validator().IfResponse(u, ifRequest(), testNow)
	if resp == nil || resp.Status != 307 || resp.Header.Get("Location") != "http://auth.example/" {
		t.Fatalf("IfResponse = %+v", resp)
	}
}

// Like the specification's second example: a token minted into the Location, with iss and iat filled in, and
// catifdata carrying the URI.
func TestCatifMintsATokenIntoAHeader(t *testing.T) {
	v := minting()
	mint := map[int64]any{1: nil, 6: nil, 320: []any{1}}
	text := claimsToken(t, map[any]any{4: testNow.Unix() - 1, 322: map[int64]any{4: []any{302, map[string]any{"Location": []any{"https://auth.example/?CAT=", mint}}, "r1"}}})
	resp := v.IfResponse(refusal(t, v, text, ifRequest()), ifRequest(), testNow)
	if resp == nil || resp.Status != 302 {
		t.Fatalf("IfResponse = %+v", resp)
	}
	loc := resp.Header.Get("Location")
	const prefix = "https://auth.example/?CAT="
	if len(loc) <= len(prefix) || loc[:len(prefix)] != prefix {
		t.Fatalf("Location = %q", loc)
	}
	minted := loc[len(prefix):]
	tok, err := v.Validate(minted)
	if err != nil {
		t.Fatalf("the minted token does not validate: %v", err)
	}
	if tok.Claims.Issuer == nil || *tok.Claims.Issuer != "cdn" || tok.Claims.IssuedAt == nil || tok.Claims.IssuedAt.Unix() != testNow.Unix() {
		t.Errorf("minted iss, iat = %v, %v", tok.Claims.Issuer, tok.Claims.IssuedAt)
	}
	raw, _ := b64u.DecodeString(minted)
	msg, err := cwt.VerifyMessage(raw, func([]byte) (cwt.Key, error) { return cwt.Key{Algorithm: cwt.HMAC256x256, Material: renewKey}, nil })
	if err != nil {
		t.Fatal(err)
	}
	var claims map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(msg.Payload, &claims); err != nil {
		t.Fatal(err)
	}
	var data []string
	if err := cbor.Unmarshal(claims[320], &data); err != nil || len(data) != 1 || data[0] != b64u.EncodeToString([]byte("https://cdn.example/a.ts")) {
		t.Errorf("catifdata = %q, %v; want the URI without the token, base64url", data, err)
	}
}

func TestCatifSubstitutions(t *testing.T) {
	text := claimsToken(t, map[any]any{4: testNow.Unix() - 1, 322: map[int64]any{4: []any{401, map[string]any{
		"X-Info": []any{"a", 0, "b", 1, "c", 2, -5, 99, map[int64]any{1: nil}},
	}}}})
	resp := validator().IfResponse(refusal(t, validator(), text, ifRequest()), ifRequest(), testNow)
	keys, _ := cbor.Marshal([]int64{4})
	want := "a" + b64u.EncodeToString([]byte("https://cdn.example/a.ts?CAT=old")) + "b" + b64u.EncodeToString([]byte("https://cdn.example/a.ts")) + "c" + b64u.EncodeToString(keys)
	if resp == nil || resp.Header.Get("X-Info") != want {
		t.Fatalf("X-Info = %q, want %q (unknown integers and, without Issuance, maps become empty strings)", resp.Header.Get("X-Info"), want)
	}
}

func TestCatifMatching(t *testing.T) {
	action := []any{403}
	cases := []struct {
		name  string
		catif any
		want  bool
	}{
		// {9: [410], [5, 4]: [403]}, written out because a Go map cannot have an array key.
		{"a label set holding the refusing claim", cbor.RawMessage(fromHex(t, "a2 09 81 19019a 82 05 04 81 190193")), true},
		{"another claim only", map[any]any{int64(3): action}, false},
		{"a status out of range", map[any]any{int64(4): []any{999}}, false},
		{"an action that is not an array", map[any]any{int64(4): "x"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := claimsToken(t, map[any]any{4: testNow.Unix() - 1, 322: tc.catif})
			resp := validator().IfResponse(refusal(t, validator(), text, ifRequest()), ifRequest(), testNow)
			if (resp != nil) != tc.want {
				t.Fatalf("IfResponse = %+v, want a response %v", resp, tc.want)
			}
		})
	}
}

// An invalid token never yields an Unacceptable, so catif cannot be processed for it (section 4.9.1).
func TestCatifNeverForInvalidTokens(t *testing.T) {
	_, err := validator().ValidateRequest(claimsToken(t, map[any]any{310: 2, 322: map[int64]any{310: []any{307}}}), ifRequest())
	var u *cat.Unacceptable
	if errors.As(err, &u) {
		t.Fatalf("an unsupported token produced an Unacceptable: %v", err)
	}
}

func TestUnacceptableKnowsTheClaim(t *testing.T) {
	for want, claims := range map[int64]map[any]any{
		1:   {1: "someone else"},
		3:   {3: "elsewhere"},
		5:   {5: testNow.Unix() + 100},
		313: {313: []string{"POST"}},
		314: {314: [][]byte{[]byte("h2")}},
		319: {319: []byte("key")},
		316: {316: []string{"FR"}},
	} {
		req := ifRequest()
		req.Connection = &cat.Connection{TLS: true, ALPN: "h3"}
		req.Location = &cat.Location{Country: "CA"}
		if u := refusal(t, validator(), claimsToken(t, claims), req); u.Claim != want {
			t.Errorf("refused by claim %d, want %d", u.Claim, want)
		}
	}
	var _ http.Header = (&cat.IfResponse{}).Header
}

// A header value from a token that would break the response's framing yields no response at all.
func TestCatifRefusesHeaderInjection(t *testing.T) {
	for name, header := range map[string]map[string]any{
		"a line break in a value": {"Location": "https://a.example/\r\nSet-Cookie: x=1"},
		"a space in a name":       {"Bad Name": "x"},
	} {
		text := claimsToken(t, map[any]any{4: testNow.Unix() - 1, 322: map[int64]any{4: []any{302, header}}})
		if resp := validator().IfResponse(refusal(t, validator(), text, ifRequest()), ifRequest(), testNow); resp != nil {
			t.Errorf("%s: IfResponse = %+v, want nil", name, resp)
		}
	}
}

// Without a kid in the action, a map becomes the empty string, even when a default key exists (section 4.9.1).
func TestCatifMintsOnlyWithAKid(t *testing.T) {
	v := renewer() // its Issuance gives a key for kid ""
	text := claimsToken(t, map[any]any{4: testNow.Unix() - 1, 322: map[int64]any{4: []any{302, map[string]any{"Location": []any{"x=", map[int64]any{}}}}}})
	if resp := v.IfResponse(refusal(t, v, text, ifRequest()), ifRequest(), testNow); resp == nil || resp.Header.Get("Location") != "x=" {
		t.Fatalf("IfResponse = %+v, want Location x= with the map left empty", resp)
	}
}

func TestCatifBoundaries(t *testing.T) {
	cases := []struct {
		name  string
		catif any
		want  bool
	}{
		{"status 100", map[int64]any{4: []any{100}}, true},
		{"status 599", map[int64]any{4: []any{599}}, true},
		{"status 99", map[int64]any{4: []any{99}}, false},
		{"status 600", map[int64]any{4: []any{600}}, false},
		{"a tab in a value", map[int64]any{4: []any{302, map[string]any{"X": "a\tb"}}}, true},
		{"a space in a value", map[int64]any{4: []any{302, map[string]any{"X": "a b"}}}, true},
		{"a unit separator in a value", map[int64]any{4: []any{302, map[string]any{"X": "a\x1fb"}}}, false},
		{"a delete in a value", map[int64]any{4: []any{302, map[string]any{"X": "a\x7fb"}}}, false},
		// {[5, 6]: [403]}: a label set without the refusing claim.
		{"a label set without the refusing claim", cbor.RawMessage(fromHex(t, "a1 82 05 06 81 190193")), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := claimsToken(t, map[any]any{4: testNow.Unix() - 1, 322: tc.catif})
			resp := validator().IfResponse(refusal(t, validator(), text, ifRequest()), ifRequest(), testNow)
			if (resp != nil) != tc.want {
				t.Fatalf("IfResponse = %+v, want a response %v", resp, tc.want)
			}
		})
	}
}
