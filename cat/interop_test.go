package cat_test

// Fixtures from other CAT implementations, judged by what CTA-5007-B requires (decision 0026). Each fixture also
// records what its source project expected; where the two differ, the note says why, and this test asserts the
// specification. Sources, commits and licences are in testdata/interop/SOURCES.md.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

type interopFixture struct {
	Name          string   `json:"name"`
	Source        string   `json:"source"`
	Token         string   `json:"token"`
	KeyHex        string   `json:"key_hex"`
	KeyText       string   `json:"key_text"`
	Issuer        string   `json:"issuer"`
	Audiences     []string `json:"audiences"`
	URI           string   `json:"uri"`
	At            int64    `json:"at"`
	SourceExpects string   `json:"source_expects"`
	SpecRequires  string   `json:"spec_requires"`
	Note          string   `json:"note"`
}

var interopKinds = map[string]error{
	"malformed":    cwt.ErrMalformed,
	"verification": cwt.ErrVerification,
	"unsupported":  cwt.ErrUnsupported,
	"unacceptable": cat.ErrUnacceptable,
}

func TestInteropFixtures(t *testing.T) {
	files, err := filepath.Glob("testdata/interop/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no interop fixtures found: %v", err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var fixtures []interopFixture
		if err := json.Unmarshal(raw, &fixtures); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, f := range fixtures {
			t.Run(filepath.Base(file)+"/"+f.Source+"/"+f.Name, func(t *testing.T) {
				key := []byte(f.KeyText)
				if f.KeyHex != "" {
					if key, err = hex.DecodeString(f.KeyHex); err != nil {
						t.Fatal(err)
					}
				}
				v := &cat.Validator{
					Keys: func([]byte) (cat.Key, error) {
						return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: key}, Issuer: f.Issuer}, nil
					},
					Audiences: f.Audiences,
					Now:       func() time.Time { return time.Unix(f.At, 0) },
				}
				var verr error
				if f.URI != "" {
					_, verr = v.ValidateRequest(f.Token, &cat.Request{Method: "GET", URI: f.URI})
				} else {
					_, verr = v.Validate(f.Token)
				}
				if f.SpecRequires == "accept" {
					if verr != nil {
						t.Fatalf("refused, the specification requires acceptance: %v (%s)", verr, f.Note)
					}
					return
				}
				kind, ok := interopKinds[f.SpecRequires]
				if !ok {
					t.Fatalf("unknown spec_requires %q", f.SpecRequires)
				}
				if !errors.Is(verr, kind) {
					t.Fatalf("got %v, the specification requires an error wrapping %v (%s)", verr, kind, f.Note)
				}
			})
		}
	}
}
