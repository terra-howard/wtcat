# Measurements of the process

Each task's prediction is committed before the task starts, then the actual result is added after. A prediction
is never edited once committed; a wrong one is recorded as wrong.

**Definitions.** A *round* is one run of `go test` that fails to compile, or fails a test the task targets, and
is followed by a fix. *Time* is wall-clock from the commit of the prediction to the commit of the task, read from
`date`. *First verify* is whether the RFC vector verified on the first run that compiled.

## 2026-11-14: implementing decision 0006, under the delegation experiment

Predictions committed at 15:22:33 EST, before any implementation.

| Task | Predicted rounds | Predicted time | Predicted first verify | Actual rounds | Actual time | Actual first verify |
|---|---|---|---|---|---|---|
| 1. `DecodeClaims` and the claim rules of decision 0008 | 2 | 15 min | yes (A.1) | 0 | under 2 min (15:22:33 to 15:24:11) | yes |
| 2. COSE envelope and header rules, `VerifyMac0` | 3 | 25 min | yes (A.4) | 0 | about 4 min (15:24:11 to 15:28:38) | yes |
| 3. `VerifySign1` with ES256 | 2 | 15 min | yes (A.3) | 0 | about 2 min (15:28:38 to 15:30:54) | yes |
| 4. PS256 for `VerifySign1` (prediction committed at 15:31:51, recalibrated from tasks 1 to 3) | 1 | 4 min | yes (COSE WG rsa-pss-01, about 85%) | 0 | about 2 min (15:31:51 to 15:32:47) | yes |
| 5. `Claims.CheckTime` under decision 0010 (prediction committed at 15:33:39) | 1 | 4 min | not applicable (no outside vector; boundary tests, about 75% all pass first run) | 0 | about 2 min (15:33:39 to 15:34:22) | all passed first run |
| 6. Fuzz targets under decision 0011, 60 s each (prediction committed at 15:34:43) | 1 | 6 min | no panics and no unclassified errors found, about 70% | 0 | about 5 min (15:34:43 to 15:38:34), 3 min of it fuzzing | none found: 15,833,193 inputs to `DecodeClaims`, 18,042,147 to `VerifyMac0`, 17,899,962 to `VerifySign1` |
| 7. `Verifier` under decision 0012, with a refactor of the COSE layer (prediction committed at 15:39:23) | 1 | 6 min | RFC vectors verify through it first run, about 85%; all tests pass first run, about 65% | 0 | about 5 min (15:39:23 to 15:41:51), including a 40 s regression fuzz (6,904,864 and 5,368,626 inputs, none failing) | yes; yes |
| 8. Mutation testing of `cwt` under decision 0013 (prediction committed at 15:42:32) | not applicable | 8 min | test efficacy at least 80%, about 60%; survivors mostly in overflow guards or error wrapping rather than verification | not applicable | about 8 min (15:42:32 to 15:45:28) | Gremlins blocked by the permission system; a hand spot-check of 15 mutants ran instead (table below). Efficacy 8 of 10 non-equivalent mutants before fixes (the 80% bound held), 10 of 10 after. The second half was wrong: the two real gaps were in the RSA key-size and ES256 signature-length rules, not in overflow guards or error wrapping |
| 9. `ExampleVerifier` and a how-to guide (prediction committed at 15:46:11) | 0 | 4 min | the example's output check passes first run, about 90% | | | |

Confidence, stated so it can be scored: first verify on A.4 at about 70%, since HMAC 256/64 truncation and the
exact bytes of the MAC structure are easy to get subtly wrong; on A.3 at about 80%; on A.1 at about 95%.

## Hand mutation spot-check, task 8

Gremlins (decision 0013) was not run: the permission system declined to download and execute a third-party tool
while the owner was away. Instead, 15 faults were planted by hand in the security-relevant lines, one at a time;
the full test suite ran against each; each file was restored from Git afterwards. No outside code ran.

| Mutant | Result |
|---|---|
| Accept a wrong MAC tag | killed |
| Drop the MAC tag-length check | equivalent: `hmac.Equal` also compares lengths |
| Allow `alg` in the unprotected header | equivalent: the "alg missing from the protected header" check still rejects it |
| Drop the header allow-list | killed |
| Accept a CWT tag not followed by a COSE tag | equivalent: decoding the inner array as a tag fails |
| Truncate HMAC 256/256 to 8 bytes | killed |
| Drop the P-256 curve check | equivalent: the 64-byte rule rejects every P-384 signature (96 bytes) |
| Lower the RSA floor to 1024 bits | **survived**, then killed by `TestPS256RejectsKeysBelow2048Bits` |
| Accept a short ES256 signature | **survived**, then killed by `TestVerifySign1RejectsNonCanonicalES256` |
| `exp` boundary off by one | killed |
| `nbf` boundary off by one | killed |
| Drop the claim-tag rule | equivalent: each registered claim's type check rejects a tag |
| Drop the `Verifier` allow-list | killed |
| Drop the tag-and-algorithm agreement check | killed |
| Drop `RequireExpiry` | killed |

**What the two survivors were.** The 1024-bit test reused a signature from a different key, so it failed whether
or not the size rule existed. The short-signature test dropped an arbitrary byte, so it failed whether or not the
length rule existed; the meaningful case drops a leading zero from `s`, keeping the value, which the loosened rule
would have accepted as a non-canonical encoding of a valid signature. Both tests now isolate their rule.

**A flaw in the harness itself.** The first pass counted two mutants as killed when they had only broken the
build (removing a check left an import unused). The re-run checks that a mutant compiles before testing it.
