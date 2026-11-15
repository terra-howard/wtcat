package cat

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

func catnipOf(t *testing.T, members ...any) []byte {
	t.Helper()
	return enc(t, members)
}

func v4(length int, b []byte) cbor.Tag { return cbor.Tag{Number: 52, Content: []any{length, b}} }
func v6(length int, b []byte) cbor.Tag { return cbor.Tag{Number: 54, Content: []any{length, b}} }

func TestDecodeCatnip(t *testing.T) {
	nets, err := decodeCatnip(catnipOf(t, uint64(64500), v4(24, []byte{192, 0, 2}), v6(48, []byte{0x20, 0x01, 0x0d, 0xb8}), v4(0, []byte{})))
	if err != nil {
		t.Fatalf("decodeCatnip: %v", err)
	}
	want := []netMatch{
		{asn: 64500},
		{prefix: netip.MustParsePrefix("192.0.2.0/24")},
		{prefix: netip.MustParsePrefix("2001:db8::/48")},
		{prefix: netip.MustParsePrefix("0.0.0.0/0")},
	}
	if len(nets) != len(want) {
		t.Fatalf("got %d members, want %d", len(nets), len(want))
	}
	for i := range want {
		if nets[i] != want[i] {
			t.Errorf("member %d = %+v, want %+v", i, nets[i], want[i])
		}
	}
}

func TestDecodeCatnipRefuses(t *testing.T) {
	sixteen := make([]byte, 16)
	sixteen[0] = 0x20
	cases := []struct {
		name  string
		value []byte
	}{
		{"not an array", enc(t, uint64(1))},
		{"an empty array", catnipOf(t)},
		{"a text member", catnipOf(t, "192.0.2.0/24")},
		{"a negative integer", catnipOf(t, -1)},
		{"another tag", catnipOf(t, cbor.Tag{Number: 53, Content: []any{24, []byte{192, 0, 2}}})},
		{"a tagged ASN", catnipOf(t, cbor.Tag{Number: 1000, Content: uint64(64500)})},
		{"a full IPv4 address, which must be encrypted", catnipOf(t, cbor.Tag{Number: 52, Content: []byte{192, 0, 2, 1}})},
		{"a full IPv6 address, which must be encrypted", catnipOf(t, cbor.Tag{Number: 54, Content: sixteen})},
		{"an IPv4 prefix longer than 24 bits", catnipOf(t, v4(25, []byte{192, 0, 2, 128}))},
		{"an IPv6 prefix longer than 56 bits", catnipOf(t, v6(57, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x80}))},
		{"an IPv4 prefix length beyond 32", catnipOf(t, v4(33, []byte{1}))},
		{"more prefix bytes than the length needs", catnipOf(t, v4(8, []byte{192, 1}))},
		{"a trailing zero byte, which RFC 9164 omits", catnipOf(t, v4(24, []byte{192, 0, 0}))},
		{"a bit set beyond the prefix length", catnipOf(t, v4(7, []byte{0xc1}))},
		{"the address-with-prefix form", catnipOf(t, cbor.Tag{Number: 52, Content: []any{[]byte{192, 0, 2, 1}, 24}})},
		{"a prefix of three elements", catnipOf(t, cbor.Tag{Number: 52, Content: []any{24, []byte{192, 0, 2}, 1}})},
		{"a tagged prefix length", catnipOf(t, cbor.Tag{Number: 52, Content: []any{cbor.Tag{Number: 1000, Content: 24}, []byte{192, 0, 2}}})},
		{"prefix bytes that are text", catnipOf(t, cbor.Tag{Number: 52, Content: []any{24, "abc"}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeCatnip(tc.value); !errors.Is(err, cwt.ErrMalformed) {
				t.Fatalf("got %v, want an error wrapping cwt.ErrMalformed", err)
			}
		})
	}
}

func TestCatnipMatches(t *testing.T) {
	nets, err := decodeCatnip(catnipOf(t, uint64(64500), v4(24, []byte{192, 0, 2}), v6(32, []byte{0x20, 0x01, 0x0d, 0xb8})))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ip   string
		asn  uint32
		want bool
	}{
		{"an IPv4 address in the prefix", "192.0.2.77", 0, true},
		{"an IPv4 address outside it", "198.51.100.1", 0, false},
		{"an IPv4-mapped IPv6 address counts as IPv4", "::ffff:192.0.2.77", 0, true},
		{"an IPv6 address in the prefix", "2001:db8:1::1", 0, true},
		{"an IPv6 address outside it", "2001:db9::1", 0, false},
		{"a listed ASN", "198.51.100.1", 64500, true},
		{"an unlisted ASN", "198.51.100.1", 64501, false},
		{"no address and no ASN", "", 0, false},
	} {
		var ip netip.Addr
		if tc.ip != "" {
			ip = netip.MustParseAddr(tc.ip)
		}
		if got := catnipMatches(nets, ip, tc.asn); got != tc.want {
			t.Errorf("%s: catnipMatches = %v, want %v", tc.name, got, tc.want)
		}
	}
	asnZero, err := decodeCatnip(catnipOf(t, uint64(0)))
	if err != nil {
		t.Fatal(err)
	}
	if catnipMatches(asnZero, netip.Addr{}, 0) {
		t.Error("ASN 0 means unknown, so a listed 0 must not match an unknown ASN")
	}
}
