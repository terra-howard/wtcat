# How to run the tests against CTA-5007-B's own examples

The specification's HMAC 256/256 and PS256 examples are strong outside test vectors, but they are not licensed for
republication, so they are not in this repository ([decision 0014](../decisions/0014-using-cta-5007-b-in-public.md)).
This guide extracts them from your own copy and runs the tests that use them.

You need a copy of CTA-5007-B, which the Consumer Technology Association offers as a free download, and `pdftotext`
from Poppler.

## 1. Convert your copy to text

From the repository root, without `-layout`:

```sh
pdftotext "CTA-5007-B.pdf" cta.txt
```

## 2. Extract the examples

```sh
go run ./cmd/ctaexamples cta.txt
```

It finds the examples by their structure, confirms each key by verifying its token, and writes them to
`testdata/cta-local/examples.json`, which Git ignores. It reports the length of each value it found. If it reports
an error instead, the document's layout differs from the edition this program was written for; nothing is written,
so no wrong vector can be used.

## 3. Run the tests

```sh
go test -tags cta ./cat
```

The tests check that each example is accepted for a request under the path its own `catu` names, refused outside
it, refused without a request, and refused with the wrong key. Without the extracted file they fail with these
instructions, rather than pass having checked nothing.

The specification's ES256 examples are left out: its published ES256 key is a secp256k1 key, not P-256, and the
examples do not verify with it on either curve.

Delete `cta.txt` and `testdata/cta-local/` when you are done if you do not want copies of the document's examples
on disk.
