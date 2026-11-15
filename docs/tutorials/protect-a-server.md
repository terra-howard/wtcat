# Tutorial: protect a small server with Common Access Tokens

In this tutorial you will build a small web server that serves files only to requests carrying a valid Common Access
Token, and a command that issues those tokens. You will then watch the server accept a token, and refuse requests
without one, for the wrong path, and after the token has expired.

It takes about fifteen minutes. You need Go 1.26 or later, `curl`, and a POSIX shell such as Git Bash on Windows.
The finished program is [examples/catdemo/main.go](../../examples/catdemo/main.go) in this repository.

## 1. Make a project

Create a directory for the program and make it a Go module:

```sh
mkdir catdemo
cd catdemo
go mod init example.com/catdemo
```

Add wtcat. Until it is published, point Go at a clone of this repository instead, here one beside `catdemo`:

```sh
go mod edit -require github.com/terra-howard/wtcat@v0.0.0 -replace github.com/terra-howard/wtcat=../wtcat
```

## 2. Write the program

Create `main.go` with this content:

```go
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
```

Then fetch what it needs:

```sh
go mod tidy
```

The program does two things. `catdemo token SECONDS` issues a token whose claims say who issued it (`iss`), when it
expires (`exp`), and which paths it opens (`catu`: any path starting with `/videos/`). `catdemo serve` runs a
server whose every response goes through the CAT middleware.

## 3. Issue a token

```sh
go run . token 60
```

It prints one line, the token, beginning with `0YRDoQEF`. Your token will differ in its later characters, because it
holds an expiry time.

## 4. Start the server

In a second terminal, in the same directory:

```sh
go run . serve
```

It prints `listening on http://localhost:8080` and waits. Leave it running.

## 5. Fetch with the token

Back in the first terminal, issue a token into a variable and use it in a request:

```sh
TOKEN=$(go run . token 60)
curl -i "http://localhost:8080/videos/intro.mp4?CAT=$TOKEN"
```

The response starts with `HTTP/1.1 200 OK`, carries `Cache-Control: private`, and ends with:

```
here is /videos/intro.mp4
```

## 6. Watch it refuse

Without the token:

```sh
curl -i http://localhost:8080/videos/intro.mp4
```

The answer is `HTTP/1.1 401 Unauthorized`. With the token, but for a path it does not open:

```sh
curl -i "http://localhost:8080/admin?CAT=$TOKEN"
```

Again `401`. With a token that has already expired, issued five seconds in the past:

```sh
OLD=$(go run . token -5)
curl -i "http://localhost:8080/videos/intro.mp4?CAT=$OLD"
```

`401` once more.

## 7. Send the token in a header instead

Tokens can also travel in the `CTA-Common-Access-Token` header field:

```sh
curl -i -H "CTA-Common-Access-Token: \"$TOKEN\"" http://localhost:8080/videos/intro.mp4
```

The answer is `200` again, and the path in the URL no longer carries the token.

Stop the server with Ctrl+C when you are done.

## What you have done

You issued tokens with `cwt.Issue`, protected a handler with `cathttp`'s middleware, and saw the validator enforce
three claims: the issuer, the expiry, and the path. From here:

- [How to validate a CAT](../how-to/validate-a-cat.md) covers the settings a real deployment needs: keys by
  `kid`, audiences, proxies, renewal.
- [Why the validator is built the way it is](../explanation/design.md) explains the choices behind what you saw.
