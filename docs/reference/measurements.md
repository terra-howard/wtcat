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
| 9. `ExampleVerifier` and a how-to guide (prediction committed at 15:46:11) | 0 | 4 min | the example's output check passes first run, about 90% | 0 | about 2 min (15:46:11 to 15:46:35) | yes |
| 11. Gremlins v0.6.0 on `cwt`, after the owner allowed it (prediction committed at 15:57:54) | not applicable | 5 min | test efficacy (killed over killed plus lived) at least 85%, about 65%; lived mutants mostly where a second check guards the same rule, as the hand spot-check found | not applicable | 39 s of mutation testing; analysis to 16:01:22 | efficacy 87.30% (110 killed, 16 lived, 22 not covered; mutator coverage 85.14%). First half held. Second half partly wrong: 7 of 16 lived mutants were equivalent, but 9 were real gaps, two of which would panic (an empty payload, a typed-nil key) |
| 11b. Gremlins re-run after tests for the 9 real gaps and 3 uncovered paths (prediction committed at 16:01:22) | not applicable | 4 min | lived falls to the 7 equivalent mutants; the 11 case-expression mutants stay not covered even though tests reach them (a coverage artifact), about 70% | not applicable | 16:01:22 to 16:04:15, three Gremlins runs of about 39 s each | held. With the timeout coefficient at 10: 119 killed, 7 lived (exactly the 7 equivalent), 22 not covered, 0 timed out; efficacy 94.44%. All 18 case-expression mutants stayed not covered, including three branches the new tests demonstrably reach, which confirms the coverage artifact; the other 4 are constants. A run at the default timeout reported 13 timeouts, 11 of them mutants killed outright in the first run, so they were load, not hangs |
| 12. Refactor `cwt` so every test file pairs with its subject by name (prediction committed at 16:21:37) | 1 | 6 min | the list of test names is identical before and after, and the census stays green, about 85% | 0 | about 8 min (16:21:37 to 16:24:05) | yes: 46 test, fuzz and example names identical (`go test -list`, diffed); census green |

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

## Gremlins, task 11

Run with `go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash --integration --invert-logical
--invert-loopctrl --timeout-coefficient 10 ./cwt`, after the owner allowed it.

| Run | Killed | Lived | Not covered | Timed out | Efficacy |
|---|---|---|---|---|---|
| First, before new tests | 110 | 16 | 22 | 0 | 87.30% |
| After new tests, default timeout | 106 | 7 | 22 | 13 | 93.81% |
| After new tests, timeout coefficient 10 | 119 | 7 | 22 | 0 | 94.44% |

**The nine real gaps the first run found,** each now killed by a test (written in `cwt/mutation_gaps_test.go`, then moved beside its subject in task 12): half and
single precision dates, a non-float simple value in a date, tagged claims outside 1 to 7 (which RFC 8392 allows),
claim key `MaxInt64`, an empty payload (the mutant indexed it and would panic), and typed-nil ECDSA and RSA keys
(the mutants dereferenced them and would panic). Tests were also added for three paths no test reached: a foreign
COSE tag given to the `Verifier`, a payload that is not a byte string, and an allowed algorithm the package cannot
verify.

**The seven equivalent mutants,** left alone: the CWT-tag-inner check (decoding as a tag fails anyway), the
header label bound (any label other than `alg` and `kid` is refused anyway), the sentinel test in `wrapMalformed`
(the error keeps its kind either way), the two overflow guards in `CheckTime` (at the exact limit the comparison
cannot succeed either way), and two boundaries of the claim-tag rule (the type check rejects a tag anyway).

**The 22 not covered:** 18 are `switch` case expressions, which this tool reports as not covered even where a test
demonstrably runs the branch; 4 are the negative algorithm constants, which the RFC and working group vectors
exercise directly.

## 2026-11-14 evening: decisions 0015 and 0016, and `cat` phase 1, under the delegation experiment

Each prediction is committed before its task starts. *Outcome* states a checkable claim with a confidence.

| Task | Predicted rounds | Predicted time | Predicted outcome | Actual rounds | Actual time | Actual outcome |
|---|---|---|---|---|---|---|
| 14. `cwt.VerifyMessage` with keys bound to one algorithm (prediction committed at 18:51:55) | 1 | 8 min | all new tests pass on the first compiled run, about 70%; no existing test changes, about 95% | 0 | about 3 min (18:51:26 to 18:54:25) | both held: the new tests passed on the first compiled run, and no existing test changed. A 30 s fuzz of `VerifyMessage` ran 6,311,846 inputs with none failing. The prediction's own timestamp, 18:51:55, was typed instead of pasted from `date`; the commit that sealed it is 18:51:26 |
| 15. `cat` package begins: strict base64url decoding with or without padding, and the length limit | 0 | 5 min | all new tests pass on the first compiled run, about 75% | 0 | about 1 min (18:54:52 to 18:55:39) | held. The code was written before the tests were seen to fail, so two hand mutants stood in for that check: dropping strict decoding and dropping the alphabet check each failed the rejection test |
| 16. Deterministic-encoding checker (RFC 8949 4.2.1 without map order, plus 4.2.2's first rule) | 1 | 10 min | all new tests pass on the first compiled run, about 55%; RFC 8392's A.1, A.3 and A.4 pass the checker, about 90%; the specification's HMAC and PS256 examples pass it (checked locally, not committed), about 85%; a 60 s fuzz finds nothing, about 75% | 0 | about 4 min (18:56:55 to 19:01:14) | all four held: first compiled run passed; RFC 8392's tokens pass; all four of the specification's example tokens pass, ES256 included (the checker sees structure, not signatures); 24,337,378 fuzz inputs, none failing, each accepted input confirmed well formed by the CBOR library. **But the tests were weaker than the pass suggested:** of 17 hand mutants, 6 survived at first (the bignum 8-byte boundary, simple value 31, and four half-precision boundaries). Six new test cases and two boundary tables killed all but one, which is equivalent (at exponent -25 the implicit bit always fails the multiple-of-2^-24 test) |
| 17. `cat` claims decoding: core claims, `catv`, tag rules, `NumericDate`, and refusing required claims not yet enforced | 1 | 8 min | all new tests pass on the first compiled run, about 60%; hand mutants of the claim rules all killed on the first try, about 40% | 2 | about 4 min (19:02:13 to 19:06:39) | first half wrong: two rounds, a name clash with task 15's `decodeText` and a test input the CBOR library refused to encode (tag 0 on an integer). Second half wrong too, as the 40% expected: of 15 hand mutants, 6 survived. Four were equivalent (a tag or wrong type already fails each claim's type check; the CBOR library already returns an empty `cti` as non-nil, so that line was removed). Two were real gaps at exactly 2^63 and -2^63, now tested. **The fuzzer then found a defect on its first input:** a tiny negative float date gave a fraction of exactly 1, because `f - floor(f)` rounds for small negative `f`. Comparisons were still right; the documented range of `Fraction` was not. Fixed, with a regression test and the saved input; 9,998,627 further inputs found nothing |
| 18. `cat.Validator`: the pipeline, acceptance of `iss`, `aud`, `exp` and `nbf` with no leeway, and an example | 1 | 10 min | all new tests pass on the first compiled run, about 55%; hand mutants of the acceptance rules all killed on the first try, about 50% | 0 | about 4 min (19:07:27 to 19:11:06) | both held: first compiled run passed, and all 12 hand mutants were killed on the first try (issuer rules, the empty `aud` array, both time boundaries, each of the three deterministic-encoding checks, the length limits, the clock). A 30 s fuzz of `Validate` ran 4,681,504 inputs with none failing; most stop at base64url, so the claims decoder's own fuzz carries the deeper coverage |
| 19. Decision 0014's extraction program, structure only, with `-tags cta` tests | 2 | 12 min | it recovers from the owner's copy exactly the four values the hand extraction found (tokens of 102 and 574 characters, keys of 564 and 44), about 70%; the `cta` tests pass against them, about 75% | 1 | about 3 min (19:12:25 to 19:15:03) | both held. One round: rounding a token's text down to whole 4-character groups cut its last byte when the token ended at a `/`. The program then recovered all four values from the owner's copy, each identical to the hand extraction, with no prose anchors. The `cta` tests passed, and failed with instructions when the file was moved away. A scan of all 92 tracked files for 16-character pieces of the four values found none |
| 20. Gremlins v0.6.0 on `cat`, and on `cwt` again for `VerifyMessage`, same flags as task 11 | not applicable | 6 min | `cat` efficacy at least 90%, about 60%; most lived mutants are ones the hand mutants already showed equivalent, about 55%; `cwt` efficacy stays at least 94%, about 70% | not applicable | about 11 min (19:15:26 to 19:26:13), six Gremlins runs of about 54 s | first half wrong at first: 89.16% on the first run, below the 90% bound. Second half wrong: of 22 lived, 6 marked real gaps, and work on them found that two of my own task 16 tests never tested truncation (their heads were not in shortest form, so they failed for that reason first). After the fixes, `cat` 93.66% (192 killed, 13 lived, all equivalent). Third half held: `cwt` 95.24% (140 killed, the same 7 equivalent as task 11), and all 21 new `VerifyMessage` mutants killed once a slow test key stopped causing timeouts |
| 21. Phase 1 housekeeping: a how-to for `cat`, the new fuzz targets in CI, `go.mod`'s direct dependency marker | 0 | 5 min | every snippet in the how-to matches the API exactly (checked against `go doc`), about 80%; each new fuzz target runs 30 s clean, about 85% | 0 | about 3 min (19:27:10 to 19:30:18) | both held: the how-to's snippets compiled unchanged in a temporary test against the real API; the CI loop, run locally, fuzzed `FuzzCheckDeterministic`, `FuzzDecodeClaims` and `FuzzValidate` in `cat` and `FuzzVerifyMessage` in `cwt` for 30 s each with none failing. `go mod tidy -diff` reports nothing left to tidy |
| 22. `Request`, `ValidateRequest` and `catm` (decision 0017) | 0 | 6 min | all new tests pass on the first compiled run, about 70%; hand mutants of the `catm` rules all killed on the first try, about 60% | 0 | about 1 min (19:32:31 to 19:33:55) | both held: first compiled run passed; all six hand mutants killed (one first failed to compile for a missing import and was rewritten, not counted as a survivor) |
| 23. The match engine of section 4.6.10 and `cath` | 1 | 10 min | all new tests pass on the first compiled run, about 50%; `regexp.CompilePOSIX` gives the POSIX leftmost-longest group for `a|ab`, about 80%; it refuses Perl's `\d` in POSIX mode, about 60% | 2 | about 5 min (19:34:40 to 19:39:30) | first part wrong: two rounds. One was a finding, not a slip: `regexp.CompilePOSIX` accepted `[[=a=]]` and read it as other characters, so a test expecting refusal failed; bracket constructs Go misreads are now refused before compiling (recorded in 0017). The other was Python mangling backslashes in an edit. Second and third parts held: the POSIX leftmost-longest group, and Perl's backslash-d refused. Of 13 hand mutants, 2 survived: the match-type bound at 5, equivalent because the switch refuses 5 anyway, though it exposed an untested key that would wrap to -1; and the leading `]` rule, untested. Both now tested. 7,702,502 fuzz inputs with a `cath` seed found nothing. This row's own prediction put a pipe character inside code, which breaks the table's columns when rendered |
| 24. URI normalization (RFC 9110 4.2.3, RFC 3986 6.2.2 and 6.2.3), the nine components, and `catu` | 2 | 12 min | all new tests pass on the first compiled run, about 40%; the specification's A.3 HMAC and PS256 examples are accepted for a URI under their path prefix and refused outside it, about 80% | 2 | about 4 min (19:40:15 to 19:44:19) | first part wrong, as the 40% expected: two rounds. One was planned: the tests named `cat.ErrURI` before `catu` was wired in. The other was a finding: an idempotence fuzz target failed on its first input, `0000://::`, which gave a host of `:`; scheme and host syntax are now checked, and the input is kept as a regression. Second part held: the specification's HMAC and PS256 examples are accepted for a URI under their own path prefix, read from the verified token so no example value is committed, and refused outside it. All 12 hand mutants of the normalization killed. After the fix, 7,756,739 fuzz inputs found nothing |

## Gremlins, task 20

Same command as task 11, on `./cat` and then `./cwt`.

| Run | Killed | Lived | Not covered | Timed out | Efficacy |
|---|---|---|---|---|---|
| `cat`, first | 181 | 22 | 30 | 0 | 89.16% |
| `cat`, second, same code | 172 | 19 | 30 | 12 | 90.05% |
| `cat`, after tests for the real gaps | 189 | 16 | 28 | 0 | 92.20% |
| `cat`, after slices with no spare capacity and an empty-payload test | 190 | 15 | 28 | 0 | 92.68% |
| `cat`, after the truncation tests were corrected | 192 | 13 | 28 | 0 | 93.66% |
| `cwt`, with `VerifyMessage` | 119 | 6 | 22 | 22 | 95.20% |
| `cwt`, after one shared 2048-bit test key replaced per-fixture 3072-bit keys | 140 | 7 | 22 | 0 | 95.24% |

**The real gaps, each now killed:**
- a truncated text string, where the mutant read past the end;
- a bignum tag enclosing an array;
- the head length of a bignum of 24 bytes or more;
- a double-precision NaN payload bit other than bit 0;
- a half-precision date;
- an empty payload given to the claims decoder, where the mutant indexed it and would panic.

**Two findings about the tests themselves:**
- `hex.DecodeString` decodes in place and leaves spare capacity, so a mutant that sliced past a test input's length read garbage instead of panicking. The checker's tests now cut their inputs to their length.
- The task 16 tests named "truncated byte string" and "truncated text string" used one-byte lengths below 24. Those are not in shortest form, so the checker rejected them for that reason, and truncation was never reached. Hand mutants in task 16 did not catch this, because none targeted the bounds check.

**The 13 equivalent mutants in `cat`:**
- two in an error message's arithmetic;
- the map-count bound, which a second check enforces;
- four in the half-precision conversion: the sign, and `mant + 1024` against `mant - 1024`. Neither can change whether a half value is integral;
- the infinity and NaN swap there, since both are accepted;
- the key bound at `MaxInt64`, which is an unknown claim either way;
- two `continue` statements turned into `break`. Inside a `switch`, `break` leaves only the switch, and key 0 is then ignored;
- a type check that `textClaim` repeats;
- the simple-value guard in dates, where the decoder's own error gives the same kind.

**The 28 not covered** are `switch` case expressions, the coverage artifact task 11 found.

