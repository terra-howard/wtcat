// Command census is the gate for protected tests. Run it from the repository root.
//
//	go run ./cmd/census            run the protected tests and check them against the manifest
//	go run ./cmd/census hash FILE  print a file's line-ending-normalised SHA-256, for writing manifest entries
//
// It never writes the manifest. Changing a protected test is the owner's deliberate act; see
// docs/decisions/0003-protected-tests.md.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/terra-howard/wtcat/internal/census"
)

const (
	manifestPath = "conformance/MANIFEST"
	protectedPkg = "./conformance/..."
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash" {
		os.Exit(hash(os.Args[2:]))
	}
	if len(os.Args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: census | census hash FILE...")
		os.Exit(2)
	}
	os.Exit(run())
}

func hash(files []string) int {
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "usage: census hash FILE...")
		return 2
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "census:", err)
			return 1
		}
		fmt.Printf("%s %s\n", census.NormalizedHash(data), f)
	}
	return 0
}

func run() int {
	if _, err := os.Stat("go.mod"); err != nil {
		fmt.Fprintln(os.Stderr, "census: run from the repository root (no go.mod here)")
		return 2
	}
	mf, err := os.Open(manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "census: red")
		fmt.Fprintf(os.Stderr, "  - cannot open %s: %v\n", manifestPath, err)
		return 1
	}
	entries, err := census.ParseManifest(mf)
	mf.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "census: red")
		fmt.Fprintf(os.Stderr, "  - %v\n", err)
		return 1
	}

	hashes := map[string]string{}
	for _, e := range entries {
		if _, done := hashes[e.Path]; done {
			continue
		}
		if data, err := os.ReadFile(e.Path); err == nil {
			hashes[e.Path] = census.NormalizedHash(data)
		}
	}

	// -count=1 forces a fresh run, so a cached result can never stand in for one.
	cmd := exec.Command("go", "test", "-json", "-count=1", protectedPkg)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			fmt.Fprintln(os.Stderr, "census: could not run go test:", err)
			return 2
		}
		// A non-zero exit from go test is expected when a test fails; the events say which.
	}

	report, err := census.Evaluate(entries, &out, hashes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "census:", err)
		return 2
	}
	if !report.OK() {
		fmt.Fprintln(os.Stderr, "census: red")
		for _, p := range report.Problems {
			fmt.Fprintf(os.Stderr, "  - %s\n", p)
		}
		return 1
	}
	fmt.Printf("census: green, %d protected tests passed and unchanged\n", report.Passed)
	return 0
}
