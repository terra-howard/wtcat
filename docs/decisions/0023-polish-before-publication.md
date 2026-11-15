# 0023. A polish pass before publication

- **Status:** accepted, 2026-11-15
- **Decided by:** Claude, under Terra Howard's delegation; pending her review. She may reverse it.

## Question asked

The owner asked for a pass over the code, tests and documentation, to leave them as good as they can be. Most of
what a careful review finds changes no behaviour and needs no decision. A few findings change the public API or
what the middleware does. Which of those would an expert make now, before anything is published?

## Reasoning

- **Names are cheapest to fix before the first release.** After it, a rename costs every caller a change. Before
  it, the cost is this repository's own uses.
- **Fix behaviour that is wrong, not behaviour that is merely different.** Each behaviour change below corrects a
  gap against a standard the package already claims to follow, and each gets a test that fails first.
- **Additions earn their place by what a caller would otherwise have to write.** Anything else is left out.

## Decision

1. **`cathttp.Location` becomes `cathttp.Place`.** "Location" had three meanings across the two packages: where
   a token was found (`cathttp.Location`), where the client is (`cat.Location`), and the option supplying the
   client's location (`Authorizer.Location`). The constants `InField` to `InDPoP`, and `Located.Where`, keep their
   names. `Located{Where: InCookie}` reads as before.
2. **`cwt.Algorithm` gains a `String` method,** giving "HMAC 256/64", "HMAC 256/256", "ES256" or "PS256", so
   that errors name algorithms the way RFC 9053 does. Formatting with `%d` still prints the number.
3. **The middleware's `Cache-Control` rule counts only an unqualified `private`.** A `private` directive that
   lists field names (RFC 9111 Section 5.2.2.7) lets a shared cache store the rest of the response, so it does not
   satisfy section 4.3.1.5.1. The middleware now replaces it with a plain `private`.
4. **The token field's parameters are parsed as RFC 9651 defines them, including display strings** (Section
   3.3.8), and with its limits on integers and decimals. Before this, a valid display-string parameter made the
   field malformed, and an over-long number was accepted.
5. **The middleware's response writer supports `http.Flusher`,** so that a streaming handler behind it can still
   flush. `http.ResponseController` already reached the underlying writer through `Unwrap`, but older handlers
   test for `http.Flusher` directly.
6. **Renewed and minted tokens encode their claim sets with keys in sorted order.** CTA-5007-B allows any order
   (section 4.5). Sorted order makes the same claims give the same bytes, which makes the output reproducible and
   easier to test and to debug.

## Consequences

- Callers that wrote the type name `cathttp.Location` must write `cathttp.Place`. None exist outside this
  repository.
- Error messages change wording. Error kinds do not: every `errors.Is` test holds as before.
- A response whose handler set `private="..."` is now plainly private. This can only keep a response out of a
  shared cache, never put one in.
