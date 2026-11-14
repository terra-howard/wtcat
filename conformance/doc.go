// Package conformance holds the protected tests: the promises the validator makes, checked against answers this
// project did not write.
//
// Do not edit, skip, rename or delete anything here, and do not change MANIFEST. The census gate
// (go run ./cmd/census) fails if a protected test is missing, skipped, failing or changed. Changing one is the
// owner's deliberate act, through a decision record. See docs/decisions/0003-protected-tests.md.
package conformance
