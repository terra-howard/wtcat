// Command ctaexamples extracts CTA-5007-B's HMAC 256/256 and PS256 examples from the text of your own copy of the
// document, for the tests behind the cta build tag (decision 0014). The output stays on your machine: its default
// location is listed in .gitignore.
//
//	pdftotext "CTA-5007-B.pdf" cta.txt   (without -layout)
//	go run ./cmd/ctaexamples cta.txt     (writes testdata/cta-local/examples.json)
//	go test -tags cta ./cat
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/terra-howard/wtcat/internal/ctaexamples"
)

// DefaultOutput is where the cta tests look, relative to the repository root.
const DefaultOutput = "testdata/cta-local/examples.json"

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: ctaexamples PDFTOTEXT_OUTPUT [OUTPUT_JSON]")
		os.Exit(2)
	}
	out := DefaultOutput
	if len(os.Args) == 3 {
		out = os.Args[2]
	}
	if err := run(os.Args[1], out); err != nil {
		fmt.Fprintln(os.Stderr, "ctaexamples:", err)
		os.Exit(1)
	}
}

func run(in, out string) error {
	text, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	ex, err := ctaexamples.Extract(string(text))
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(ex, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s: HMAC token %d characters, HMAC key %d, PS256 token %d, PS256 key %d; each key verified its token\n",
		out, len(ex.HMACToken), len(ex.HMACKey), len(ex.PS256Token), len(ex.PS256PublicKey))
	return nil
}
