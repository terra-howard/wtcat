# 0011. Fuzz the parsers

- **Status:** accepted, 2026-11-14
- **Decided by:** Claude, under Terra Howard's delegation for an experiment (see decision 0007). Pending her
  review; she may reverse it.

## Question asked

The validator will parse bytes from the network at CDN edges. Example-based tests cover the cases someone thought
of. What would an expert add before anyone relies on this code?

## Reasoning

Fuzzing, because the dangerous inputs are the ones nobody thought of. Go's built-in fuzzer needs no dependency.
Two properties are worth checking on every input:

1. **No panics.** A crafted token must never crash the process that checks it.
2. **Every error is classified.** Each error wraps exactly the kinds decision 0006 promises (`ErrVerification`,
   `ErrMalformed`, `ErrUnsupported`). Callers branch on those; an unclassified error would fall through their
   handling.

The seed corpus is the outside vectors already in the repository, so the fuzzer starts from real tokens and
mutates outward.

## Decision

- Fuzz targets for `DecodeClaims`, `VerifyMac0` and `VerifySign1`, checking both properties, seeded with RFC 8392
  Appendix A.
- Run each for 60 seconds now and record the result in `docs/reference/measurements.md`, with the prediction
  committed first. Any input the fuzzer finds becomes a permanent regression case under `testdata/fuzz/`, which
  `go test` replays on every run.
- Longer fuzzing belongs in CI once the repository has it.
