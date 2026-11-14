# 0005. CBOR and COSE support

- **Status:** accepted, 2026-11-14 (option B)
- **Decided by:** Terra Howard

## Context

A Common Access Token is a CBOR Web Token (RFC 8392) protected with COSE. Akamai's CAT module, one public reading
of the format, creates and verifies tokens with HS256 (an HMAC) and with ES256 and PS256 (signatures). COSE carries
a single-recipient MAC as COSE_Mac0 and a single signature as COSE_Sign1; which structures CAT permits is
`spec-needed` until CTA-5007-B is available, so this starts with those two. So the validator needs a CBOR decoder
and COSE_Mac0 and COSE_Sign1 verification. COSE_Encrypt0 can come later.

Candidates, checked through the GitHub API on 2026-11-14:

| Library | Licence | Activity | Covers |
|---|---|---|---|
| [fxamacker/cbor][cbor] | MIT | latest release v2.10.0, 2026-10-28 | CBOR (RFC 8949) |
| [veraison/go-cose][gocose] | MPL-2.0 | latest release v1.3.0, 2024-09-27; last push 2026-10-03 | COSE_Sign1 and COSE_Sign; its README shows no COSE_Mac0 or COSE_Encrypt0 |

## Options

- **A. fxamacker/cbor plus go-cose,** with our own COSE_Mac0. Two dependencies under two licences (MPL-2.0 is
  compatible with Apache-2.0 as a dependency, but it is one more licence to track), and Mac0, the most common CAT
  form, is still ours to write.
- **B. fxamacker/cbor plus our own minimal COSE** for COSE_Mac0 and COSE_Sign1, built on the standard library's
  `crypto/hmac`, `crypto/ecdsa` and `crypto/rsa`. One MIT dependency. The COSE structures to build (RFC 9052's
  `MAC_structure` and `Sig_structure`) are small and fully specified, and RFC 8392 Appendix A's worked examples,
  already chosen as the first protected tests, check them against outside answers.
- **C. Our own CBOR as well.** No dependencies, but CBOR decoding has edge cases (indefinite lengths, duplicate map
  keys, tags) that a mature library has already met.

## Decision

B. fxamacker/cbor v2.10.0 (MIT; its one dependency, x448/float16, is also MIT) plus our own COSE_Mac0 and
COSE_Sign1. Composing standard primitives around a fully specified structure, with outside test vectors as the referee, is
a fair job for this project; a full CBOR decoder is not. Tag comparisons use `hmac.Equal`, never `==`.

[cbor]: https://github.com/fxamacker/cbor
[gocose]: https://github.com/veraison/go-cose
