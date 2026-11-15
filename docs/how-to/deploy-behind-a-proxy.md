# How to deploy behind a proxy

This guide is for running a `cathttp`-protected server behind a load balancer or reverse proxy that terminates TLS
and forwards requests over plain HTTP. In that setup the server cannot see several facts the claims depend on, and
the defaults fail closed: tokens that depend on those facts are refused. Each step below hands one fact back.

It assumes you already have a working `cat.Validator` ([How to validate a CAT](validate-a-cat.md)).

## 1. Give the public scheme

Behind the proxy every request looks like `http`. A `catu` claim that matches the scheme, or a port that is the
default for `https`, would then fail. Set the scheme clients actually used:

```go
auth := &cathttp.Authorizer{
	Validator: v,
	Scheme:    "https", // TLS ends at the proxy
}
```

Make sure the proxy forwards the original `Host` header, since the URI checked against `catu` is built from it.

## 2. Give the client's address

`RemoteAddr` is now the proxy's address, so `catnip` would judge the proxy instead of the client. Read the address
your proxy passes on, but only from a header your proxy sets itself, never one a client could send:

```go
auth.ClientIP = func(r *http.Request) netip.Addr {
	// The proxy appends the client's address to X-Forwarded-For; take the last entry, which it wrote.
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	ip, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1]))
	if err != nil {
		return netip.Addr{}
	}
	return ip
}
```

If you have an IP-to-ASN database, set `ClientASN` too; `catnip` can list autonomous systems as well as prefixes.

## 3. Give the connection's TLS facts, or decline them

`catalpn` and `cattpk` need the negotiated ALPN and the client's certificate chain. Behind a TLS-terminating proxy
the default reports "not TLS", so tokens with those claims are refused. If your proxy passes these facts on, hand
them over:

```go
auth.Connection = func(r *http.Request) *cat.Connection {
	return &cat.Connection{TLS: true, ALPN: r.Header.Get("X-Forwarded-ALPN")} // whatever header your proxy sets
}
```

If it does not, returning `nil` makes those claims ignored instead of refusing every token that carries them, which
CTA-5007-B allows for optional claims. Choose deliberately: ignoring them accepts tokens their issuer meant to
restrict.

## 4. Give the client's location, if you locate clients

`catgeoiso3166` is enforced only when you supply a location:

```go
auth.Location = func(r *http.Request) *cat.Location {
	country, region, ok := lookupPlace(r) // your GeoIP lookup
	if !ok {
		return &cat.Location{} // located nowhere: tokens restricted by place are refused
	}
	return &cat.Location{Country: country, Region: region}
}
```

Return an empty `Location` rather than `nil` when a lookup fails, so a failed lookup cannot bypass the restriction.

## 5. Share replay state across instances

Several servers behind one proxy each see only some requests. If you enforce `catreplay`, its record of used
`cti` values must be shared, for example in a cache all instances reach:

```go
v.Replay = func(cti []byte) (seen bool) {
	return store.SeenOrAdd(string(cti)) // your shared store: records cti, reports whether it was already there
}
```

Keep each `cti` at least until its token's `exp`.
