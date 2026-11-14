package cat

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/terra-howard/wtcat/cwt"
)

func TestDecodeTextAcceptsPaddedAndUnpadded(t *testing.T) {
	for _, data := range [][]byte{{0xd1}, {0xd1, 0x84}, {0xd1, 0x84, 0x43}, {0xd1, 0x84, 0x43, 0xa1}, {0xfb, 0xff, 0xbf}} {
		for _, text := range []string{base64.URLEncoding.EncodeToString(data), base64.RawURLEncoding.EncodeToString(data)} {
			got, err := decodeText(text, 100)
			if err != nil {
				t.Errorf("decodeText(%q): %v", text, err)
				continue
			}
			if !bytes.Equal(got, data) {
				t.Errorf("decodeText(%q) = %x, want %x", text, got, data)
			}
		}
	}
}

func TestDecodeTextRejectsNonCanonicalText(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"empty", ""},
		{"standard alphabet plus", "+_8"},
		{"standard alphabet slash", "-/8"},
		{"line feed inside", "0YRD\noQEF"},
		{"carriage return inside", "0YRD\roQEF"},
		{"space", "0YRD oQEF"},
		{"too little padding", "0Q="},
		{"too much padding", "0YQ=="},
		{"padding on a full block", "0YRD===="},
		{"padding in the middle", "0Q==0Q=="},
		{"non-zero trailing bits, one byte", "0R"},
		{"non-zero trailing bits, two bytes", "0YR"},
		{"non-zero trailing bits, padded", "0R=="},
		{"impossible length", "0YRDo"},
		{"non-ASCII", "0YRDé"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeText(tc.text, 100); !errors.Is(err, cwt.ErrMalformed) {
				t.Fatalf("decodeText(%q) = %v, want an error wrapping cwt.ErrMalformed", tc.text, err)
			}
		})
	}
}

func TestDecodeTextLengthLimit(t *testing.T) {
	atLimit := strings.Repeat("A", 4096)
	if _, err := decodeText(atLimit, 4096); err != nil {
		t.Fatalf("a token of exactly the limit: %v", err)
	}
	if _, err := decodeText(atLimit+"AAAA", 4096); !errors.Is(err, cwt.ErrUnsupported) {
		t.Fatalf("a token over the limit: got %v, want an error wrapping cwt.ErrUnsupported", err)
	}
}
