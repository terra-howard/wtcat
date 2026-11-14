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
| 3. `VerifySign1` with ES256 | 2 | 15 min | yes (A.3) | | | |

Confidence, stated so it can be scored: first verify on A.4 at about 70%, since HMAC 256/64 truncation and the
exact bytes of the MAC structure are easy to get subtly wrong; on A.3 at about 80%; on A.1 at about 95%.
