package cat

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/terra-howard/wtcat/cwt"
)

// decodeText decodes a token's text form (CTA-5007-B section 4.3.1.1): base64url, with or without padding.
// Decoding is strict, so each token has exactly one text form (decision 0015): only the base64url alphabet, padding
// only at the end and only as much as the length needs, and zero trailing bits. Go's decoder skips line breaks
// even in strict mode, so the alphabet is checked first. A token longer than maxLen bytes is refused unread.
func decodeText(text string, maxLen int) ([]byte, error) {
	if len(text) > maxLen {
		return nil, fmt.Errorf("%w: token is %d bytes, over the limit of %d", cwt.ErrUnsupported, len(text), maxLen)
	}
	if text == "" {
		return nil, fmt.Errorf("%w: empty token", cwt.ErrMalformed)
	}
	body := strings.TrimRight(text, "=")
	for i := 0; i < len(body); i++ {
		if !isBase64URL(body[i]) {
			return nil, fmt.Errorf("%w: byte %d of the token is not base64url", cwt.ErrMalformed, i)
		}
	}
	enc := base64.RawURLEncoding.Strict()
	if len(body) != len(text) {
		enc = base64.URLEncoding.Strict()
	}
	data, err := enc.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("%w: base64url: %v", cwt.ErrMalformed, err)
	}
	return data, nil
}

func isBase64URL(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}
