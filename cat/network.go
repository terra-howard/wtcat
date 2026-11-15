package cat

import (
	"net/netip"

	"github.com/fxamacker/cbor/v2"
)

// RFC 9164 tags for IP addresses and prefixes, the only tags CTA-5007-B allows inside catnip (section 4.6.9).
const (
	tagIPv4 = 52
	tagIPv6 = 54
)

// Section 4.6.9: an unencrypted catnip may not name a full address, or a prefix more specific than these.
const (
	maxIPv4Prefix = 24
	maxIPv6Prefix = 56
)

// netMatch is one member of a catnip claim: an autonomous system number when prefix is not valid, else a prefix.
type netMatch struct {
	asn    uint64
	prefix netip.Prefix
}

// decodeCatnip decodes a catnip claim under decision 0017.
func decodeCatnip(value cbor.RawMessage) ([]netMatch, error) {
	if len(value) == 0 || majorType(value) != majorArray {
		return nil, malformed("claim 311 (catnip) is not an array")
	}
	var items []cbor.RawMessage
	if err := decMode.Unmarshal(value, &items); err != nil {
		return nil, malformed("claim 311 (catnip): %v", err)
	}
	if len(items) == 0 {
		return nil, malformed("claim 311 (catnip) is an empty array")
	}
	out := make([]netMatch, 0, len(items))
	for _, item := range items {
		switch majorType(item) {
		case majorUnsigned:
			var asn uint64
			if err := decMode.Unmarshal(item, &asn); err != nil {
				return nil, malformed("claim 311 (catnip): %v", err)
			}
			out = append(out, netMatch{asn: asn})
		case majorTag:
			p, err := decodePrefix(item)
			if err != nil {
				return nil, err
			}
			out = append(out, netMatch{prefix: p})
		default:
			return nil, malformed("claim 311 (catnip) holds something other than an ASN or an RFC 9164 prefix")
		}
	}
	return out, nil
}

// decodePrefix decodes an RFC 9164 prefix under tag 52 or 54, refusing addresses, the address-with-prefix form,
// prefixes more specific than section 4.6.9 allows unencrypted, and prefixes not in RFC 9164's own encoding.
func decodePrefix(item cbor.RawMessage) (netip.Prefix, error) {
	var tag cbor.RawTag
	if err := decMode.Unmarshal(item, &tag); err != nil {
		return netip.Prefix{}, malformed("claim 311 (catnip): %v", err)
	}
	size, limit := 4, maxIPv4Prefix
	switch tag.Number {
	case tagIPv4:
	case tagIPv6:
		size, limit = 16, maxIPv6Prefix
	default:
		return netip.Prefix{}, malformed("claim 311 (catnip) uses tag %d; only 52 and 54 are allowed", tag.Number)
	}
	content := []byte(tag.Content)
	if majorType(content) != majorArray {
		return netip.Prefix{}, malformed("claim 311 (catnip) names a full address, which section 4.6.9 requires to be encrypted")
	}
	var parts []cbor.RawMessage
	if err := decMode.Unmarshal(content, &parts); err != nil || len(parts) != 2 {
		return netip.Prefix{}, malformed("claim 311 (catnip): a prefix is [length, bytes]")
	}
	if len(parts[0]) == 0 || majorType(parts[0]) != majorUnsigned {
		return netip.Prefix{}, malformed("claim 311 (catnip): the address-with-prefix form, or a prefix length that is not an unsigned integer")
	}
	if len(parts[1]) == 0 || majorType(parts[1]) != majorBytes {
		return netip.Prefix{}, malformed("claim 311 (catnip): prefix bytes are not a byte string")
	}
	var length uint64
	var bytes []byte
	if err := decMode.Unmarshal(parts[0], &length); err != nil {
		return netip.Prefix{}, malformed("claim 311 (catnip): %v", err)
	}
	if err := decMode.Unmarshal(parts[1], &bytes); err != nil {
		return netip.Prefix{}, malformed("claim 311 (catnip): %v", err)
	}
	switch {
	case length > uint64(8*size):
		return netip.Prefix{}, malformed("claim 311 (catnip): prefix length %d is beyond the address size", length)
	case length > uint64(limit):
		return netip.Prefix{}, malformed("claim 311 (catnip): a /%d prefix must be encrypted (section 4.6.9)", length)
	case len(bytes) > int(length+7)/8:
		return netip.Prefix{}, malformed("claim 311 (catnip): more prefix bytes than a /%d prefix needs", length)
	case len(bytes) > 0 && bytes[len(bytes)-1] == 0:
		return netip.Prefix{}, malformed("claim 311 (catnip): a trailing zero byte, which RFC 9164 omits")
	}
	if rem := length % 8; rem != 0 && len(bytes) == int(length+7)/8 && bytes[len(bytes)-1]&(0xff>>rem) != 0 {
		return netip.Prefix{}, malformed("claim 311 (catnip): a bit set beyond the /%d prefix", length)
	}
	full := make([]byte, size)
	copy(full, bytes)
	var addr netip.Addr
	if size == 4 {
		addr = netip.AddrFrom4([4]byte(full))
	} else {
		addr = netip.AddrFrom16([16]byte(full))
	}
	return netip.PrefixFrom(addr, int(length)), nil
}

// catnipMatches reports whether the client's address lies in a listed prefix, an IPv4-mapped IPv6 address counting
// as IPv4, or the client's ASN is listed and known.
func catnipMatches(nets []netMatch, ip netip.Addr, asn uint32) bool {
	ip = ip.Unmap()
	for _, n := range nets {
		if n.prefix.IsValid() {
			if ip.IsValid() && n.prefix.Contains(ip) {
				return true
			}
		} else if asn != 0 && n.asn == uint64(asn) {
			return true
		}
	}
	return false
}
