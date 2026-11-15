// Command catdemo issues a Common Access Token and serves content that only such a token can fetch.
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cathttp"
	"github.com/terra-howard/wtcat/cwt"
)

// secret is the HMAC key the issuer and the server share. Never put a real key in source code.
var secret = []byte("tutorial secret, 32 bytes long!!")

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: catdemo token SECONDS | catdemo serve")
	}
	switch os.Args[1] {
	case "token":
		seconds := 60
		if len(os.Args) > 2 {
			fmt.Sscan(os.Args[2], &seconds)
		}
		fmt.Println(issue(time.Duration(seconds) * time.Second))
	case "serve":
		serve()
	default:
		log.Fatal("usage: catdemo token SECONDS | catdemo serve")
	}
}

// issue makes a token for anything under /videos/ that expires after the given time.
func issue(lifetime time.Duration) string {
	claims := map[int64]any{
		1:   "tutorial-issuer",                              // iss
		4:   time.Now().Add(lifetime).Unix(),                // exp
		312: map[int64]any{3: map[int64]any{1: "/videos/"}}, // catu: the path must start with /videos/
	}
	payload, err := cbor.Marshal(claims)
	if err != nil {
		log.Fatal(err)
	}
	token, err := cwt.Issue(payload, cwt.SigningKey{Algorithm: cwt.HMAC256x256, KID: []byte("k1"), Material: secret})
	if err != nil {
		log.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(token)
}

// serve protects everything it serves with the CAT middleware; the token itself says which paths it opens.
func serve() {
	validator := &cat.Validator{
		Keys: func(kid []byte) (cat.Key, error) {
			if string(kid) != "k1" {
				return cat.Key{}, fmt.Errorf("unknown key %q", kid)
			}
			return cat.Key{Key: cwt.Key{Algorithm: cwt.HMAC256x256, Material: secret}, Issuer: "tutorial-issuer"}, nil
		},
	}
	auth := &cathttp.Authorizer{Validator: validator}
	content := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "here is %s\n", r.URL.Path)
	})
	http.Handle("/", auth.Middleware(content))
	log.Println("listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}
