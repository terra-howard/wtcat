# Interoperability fixtures

Tokens produced by other Common Access Token implementations, copied from their test suites as fixtures
(AGENTS.md rule 5, decision 0026). Only tokens, keys and the source test's expected outcome are taken. No code is
copied. Each fixture's `source` field gives the file and line within the repository below.

| File | Project | Repository | Commit | Licence |
|---|---|---|---|---|
| `node-cat.json` | node-cat, Eyevinn Technology AB | https://github.com/Eyevinn/node-cat | `3a5cdbfec0d494712fc8e1751989f6e69497605f` | MIT, Copyright (c) 2025 Eyevinn Technology AB |
| `rust-cat.json` | rust-cat, Fastly Inc. | https://github.com/fastly/rust-cat | `c5001a8dcf03d179fe563692fb0fba39ef5dd46d` | MIT, Copyright (c) 2025-2026 Fastly Inc. |
| `zig-common-access-token.json` | zig-common-access-token, Frank Denis | https://github.com/jedisct1/zig-common-access-token | `7f3bb3316c4b99ad31cfbfe273214324ea9f6f8f` | MIT, Copyright (c) 2025-2026 Frank Denis |

## Licences

All three projects use the MIT licence. It allows anyone to use, copy, modify and distribute the software, on one
condition: the copyright notice and the permission notice must be included in all copies or substantial portions.
A few dozen tokens from test suites are unlikely to be a substantial portion, and tokens a program outputs are
data rather than its authors' expression. The condition is met anyway: each project's licence file is copied here
unchanged from the commit above, with its copyright notice and permission notice:

- [`licenses/node-cat.LICENSE`](licenses/node-cat.LICENSE)
- [`licenses/rust-cat.LICENSE`](licenses/rust-cat.LICENSE)
- [`licenses/zig-common-access-token.LICENSE`](licenses/zig-common-access-token.LICENSE)

The MIT licence is compatible with this repository's Apache-2.0 licence, and AGENTS.md rule 5 allows tokens from
other implementations as fixtures with their source and licence recorded, which this file does.

## Keys

Most HMAC fixtures use RFC 8392's example 256-bit key (Appendix A.2.2). The rust-cat ones use the keys their tests
name, `testKey` and `testSecret`, as text.

Each fixture's `spec_requires` is the verdict CTA-5007-B and the RFCs require, and `source_expects` is what the
source project's test expected. Where they differ, `note` explains why, and `cat/interop_test.go` asserts the
specification's verdict.
