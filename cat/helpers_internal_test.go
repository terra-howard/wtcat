package cat

// Helpers shared by the internal tests in this package.

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// testRSAKey returns a fixed RSA test key of the given size from testdata (task 60). Generating RSA keys takes a
// long-tailed time, which made mutation-testing runs time out; fixed keys make every test run take about the same
// time. The files say "TESTING KEY" instead of "PRIVATE KEY", as Go's own test keys do, so secret scanners do not
// mistake them for leaked credentials. They protect nothing.
func testRSAKey(t testing.TB, bits int) (*rsa.PrivateKey, error) {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("testdata/test-rsa-%d.pem", bits))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(strings.ReplaceAll(string(raw), "TESTING KEY", "PRIVATE KEY")))
	if block == nil {
		return nil, errors.New("no PEM block in the test key file")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the test key file does not hold an RSA key")
	}
	return rk, nil
}
