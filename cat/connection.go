package cat

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
)

// Connection describes the connection a request came over, for catalpn and cattpk (decision 0021). A nil
// Request.Connection means the recipient does not supply it, and those claims are ignored.
type Connection struct {
	TLS        bool     // the request came over TLS or QUIC
	ALPN       string   // the negotiated ALPN protocol; empty if none was determined
	ClientKeys [][]byte // the DER SubjectPublicKeyInfo of each certificate in the client's chain
}

// ErrConnection means the request's connection does not satisfy the token's catalpn or cattpk claim.
var ErrConnection = fmt.Errorf("%w: the connection does not satisfy catalpn or cattpk", ErrUnacceptable)

// decodeALPNs decodes catalpn: an array of at least one untagged byte string.
func decodeALPNs(value cbor.RawMessage) ([][]byte, error) {
	if majorType(value) != majorArray {
		return nil, malformed("claim 314 (catalpn) is not an array")
	}
	var items []cbor.RawMessage
	if err := decMode.Unmarshal(value, &items); err != nil {
		return nil, malformed("claim 314 (catalpn): %v", err)
	}
	if len(items) == 0 {
		return nil, malformed("claim 314 (catalpn) is an empty array")
	}
	out := make([][]byte, 0, len(items))
	for _, item := range items {
		if len(item) == 0 || majorType(item) != majorBytes {
			return nil, malformed("claim 314 (catalpn) holds something other than an untagged byte string")
		}
		var b []byte
		if err := decMode.Unmarshal(item, &b); err != nil {
			return nil, malformed("claim 314 (catalpn): %v", err)
		}
		out = append(out, b)
	}
	return out, nil
}

// decodeTPK decodes cattpk: an untagged byte string holding a DER SubjectPublicKeyInfo.
func decodeTPK(value cbor.RawMessage) ([]byte, error) {
	if majorType(value) != majorBytes {
		return nil, malformed("claim 319 (cattpk) is not a byte string")
	}
	var b []byte
	if err := decMode.Unmarshal(value, &b); err != nil {
		return nil, malformed("claim 319 (cattpk): %v", err)
	}
	return b, nil
}

// checkConnection enforces catalpn and cattpk when the caller supplies a Connection.
func checkConnection(c *Claims, req *Request) error {
	if c.alpns == nil && c.tpk == nil || req == nil || req.Connection == nil {
		return nil
	}
	conn := req.Connection
	if !conn.TLS {
		key := int64(claimCatalpn)
		if c.alpns == nil {
			key = claimCattpk
		}
		return &keyedError{key, fmt.Errorf("%w: the request was not made over TLS", ErrConnection)}
	}
	if c.alpns != nil {
		if conn.ALPN == "" || !slices.ContainsFunc(c.alpns, func(a []byte) bool { return string(a) == conn.ALPN }) {
			return &keyedError{claimCatalpn, fmt.Errorf("%w: ALPN %q is not listed", ErrConnection, conn.ALPN)}
		}
	}
	if c.tpk != nil {
		if slices.ContainsFunc(conn.ClientKeys, func(k []byte) bool { return bytes.Equal(k, c.tpk) }) {
			return nil
		}
		return &keyedError{claimCattpk, fmt.Errorf("%w: no client certificate has the cattpk key", ErrConnection)}
	}
	return nil
}
