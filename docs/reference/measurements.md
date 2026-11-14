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
| 7. `Verifier` under decision 0012, with a refactor of the COSE layer (prediction committed at 15:39:23) | 1 | 6 min | RFC vectors verify through it first run, about 85%; all tests pass first run, about 65% | | | |

Confidence, stated so it can be scored: first verify on A.4 at about 70%, since HMAC 256/64 truncation and the
exact bytes of the MAC structure are easy to get subtly wrong; on A.3 at about 80%; on A.1 at about 95%.
