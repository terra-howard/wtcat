package cat

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/terra-howard/wtcat/cwt"
)

// mustHex decodes test hex into a slice whose capacity equals its length, so that reading past the end panics
// instead of silently reading spare capacity (hex.DecodeString decodes in place, leaving spare capacity behind).
func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad test hex %q: %v", s, err)
	}
	return b[:len(b):len(b)]
}

// RFC 8392 Appendix A, as in package cwt's tests and the protected tests.
const (
	rfcClaimsA1 = "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71"
	rfcSignedA3 = "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30"
	rfcMacedA4  = "d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200"
)

func TestCheckDeterministicAccepts(t *testing.T) {
	for _, tc := range []struct{ name, hex string }{
		{"RFC 8392 A.1 claims set", rfcClaimsA1},
		{"RFC 8392 A.3 signed CWT", rfcSignedA3},
		{"RFC 8392 A.4 MACed CWT", rfcMacedA4},
		{"0", "00"},
		{"23", "17"},
		{"24", "1818"},
		{"255", "18ff"},
		{"256", "190100"},
		{"65535", "19ffff"},
		{"65536", "1a00010000"},
		{"2^32-1", "1affffffff"},
		{"2^32", "1b0000000100000000"},
		{"2^64-1", "1bffffffffffffffff"},
		{"-1", "20"},
		{"-25", "3818"},
		{"-2^64", "3bffffffffffffffff"},
		{"byte string of 24", "5818" + strings.Repeat("00", 24)},
		{"text string", "6161"},
		{"map keys out of order (allowed by CTA-5007-B section 4.5)", "a2 02 00 01 00"},
		{"tag", "d83d d1 80"},
		{"1.5 as half", "f93e00"},
		{"5555.5 as single (RFC 8949 4.1)", "fa45ad9c00"},
		{"1000000.5 as single (RFC 8949 4.2.1)", "fa49742408"},
		{"1.1 as double", "fb3ff199999999999a"},
		{"1e300 as double", "fb7e37e43c8800759c"},
		{"smallest half subnormal", "f90001"},
		{"1.5 times 2^-24 as single: in the half subnormal range, but not a multiple of 2^-24", "fa33c00000"},
		{"2^-15 plus 2^-25 as single: ten significand bits, but below the half normal range", "fa38002000"},
		{"NaN as half", "f97e00"},
		{"infinity as half", "f97c00"},
		{"single NaN whose payload does not fit a half", "fa7f800001"},
		{"2^64 as single: integral, but too large for major type 0", "fa5f800000"},
		{"bignum too large for 64 bits", "c249" + "01" + strings.Repeat("00", 8)},
		{"24-byte bignum, with a one-byte length", "c25818" + strings.Repeat("01", 24)},
		{"two-byte simple value 32", "f820"},
		{"false, true, null", "83 f4 f5 f6"},
		{"32 nested arrays", strings.Repeat("81", 32) + "00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkDeterministic(mustHex(t, tc.hex)); err != nil {
				t.Fatalf("checkDeterministic(%s): %v", tc.hex, err)
			}
		})
	}
}

func TestCheckDeterministicRejects(t *testing.T) {
	for _, tc := range []struct{ name, hex string }{
		{"empty", ""},
		{"23 in one extra byte", "1817"},
		{"255 in two bytes", "1900ff"},
		{"65535 in four bytes", "1a0000ffff"},
		{"2^32-1 in eight bytes", "1b00000000ffffffff"},
		{"-24 in one extra byte", "3817"},
		{"byte string length in one extra byte", "580100"},
		{"text string length in one extra byte", "780161"},
		{"array count in one extra byte", "980100"},
		{"map count in one extra byte", "b8010000"},
		{"tag number in one extra byte", "d80000"},
		{"indefinite byte string", "5fff"},
		{"indefinite text string", "7fff"},
		{"indefinite array", "9fff"},
		{"indefinite map", "bfff"},
		{"lone break", "ff"},
		{"reserved additional information", "1c"},
		{"one-byte simple value below 32", "f810"},
		{"one-byte simple value 31", "f81f"},
		{"1.5 as single", "fa3fc00000"},
		{"1.5 as double", "fb3ff8000000000000"},
		{"1.0, integral, as half", "f93c00"},
		{"0.0 as half", "f90000"},
		{"negative zero as half", "f98000"},
		{"100000.0, integral, as single", "fa47c35000"},
		{"2^63, integral, as single", "fa5f000000"},
		{"-2^64, integral and fits major type 1, as single", "fadf800000"},
		{"NaN as single", "fa7fc00000"},
		{"infinity as double", "fb7ff0000000000000"},
		{"smallest half subnormal as single", "fa33800000"},
		{"bignum that fits 64 bits", "c24101"},
		{"eight-byte bignum, which fits 64 bits", "c248" + strings.Repeat("ff", 8)},
		{"bignum with a leading zero", "c249" + "00" + "01" + strings.Repeat("00", 7)},
		{"empty negative bignum", "c340"},
		{"bignum tag on an integer", "c201"},
		{"bignum tag on an array of nine", "c289" + strings.Repeat("01", 9)},
		{"24-byte bignum with a leading zero", "c25818" + "00" + strings.Repeat("01", 23)},
		{"truncated argument", "1900"},
		{"truncated byte string", "430102"}, // length 3, two bytes present
		{"truncated text string", "636161"}, // length 3, two bytes present
		{"truncated long byte string", "5818" + strings.Repeat("00", 23)},
		{"truncated array", "8201"},
		{"trailing bytes", "0102"},
		{"array count larger than the input", "9bffffffffffffffff"},
		{"byte string length larger than the input", "5bffffffffffffffff00"},
		{"invalid UTF-8", "62c328"},
		{"33 nested arrays", strings.Repeat("81", 33) + "00"},
		{"33 nested tags", strings.Repeat("c1", 33) + "00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkDeterministic(mustHex(t, tc.hex)); !errors.Is(err, cwt.ErrMalformed) {
				t.Fatalf("checkDeterministic(%s) = %v, want an error wrapping cwt.ErrMalformed", tc.hex, err)
			}
		})
	}
}

func TestSingleFitsHalf(t *testing.T) {
	for _, tc := range []struct {
		name string
		bits uint32
		want bool
	}{
		{"65504, the largest half", 0x477fe000, true},
		{"65520, eleven significand bits", 0x477ff000, false},
		{"65536, beyond the half range", 0x47800000, false},
		{"2^-14, the smallest half normal", 0x38800000, true},
		{"2^-15, a half subnormal", 0x38000000, true},
		{"2^-15 plus 2^-25", 0x38002000, false},
		{"2^-24, the smallest half subnormal", 0x33800000, true},
		{"1.5 times 2^-24", 0x33c00000, false},
		{"2^-25, below every half", 0x33000000, false},
		{"negative zero", 0x80000000, true},
		{"a single subnormal", 0x00000001, false},
		{"infinity", 0x7f800000, true},
		{"quiet NaN", 0x7fc00000, true},
		{"NaN with a low payload bit", 0x7f800001, false},
	} {
		if got := singleFitsHalf(tc.bits); got != tc.want {
			t.Errorf("singleFitsHalf(%s, %#08x) = %v, want %v", tc.name, tc.bits, got, tc.want)
		}
	}
}

func TestDoubleFitsSingle(t *testing.T) {
	for _, tc := range []struct {
		name string
		bits uint64
		want bool
	}{
		{"1.5", 0x3ff8000000000000, true},
		{"1.1", 0x3ff199999999999a, false},
		{"the largest single", 0x47efffffe0000000, true},
		{"2^128, beyond the single range", 0x47f0000000000000, false},
		{"2^-149, the smallest single subnormal", 0x36a0000000000000, true},
		{"2^-150, below every single", 0x3690000000000000, false},
		{"infinity", 0x7ff0000000000000, true},
		{"quiet NaN", 0x7ff8000000000000, true},
		{"NaN with a low payload bit", 0x7ff0000000000001, false},
		{"NaN with payload bit 1", 0x7ff8000000000002, false},
	} {
		if got := doubleFitsSingle(tc.bits); got != tc.want {
			t.Errorf("doubleFitsSingle(%s, %#016x) = %v, want %v", tc.name, tc.bits, got, tc.want)
		}
	}
}

// wellformed is an independent check, by the CBOR library, that an accepted input is one well-formed item.
var wellformed = func() cbor.DecMode {
	dm, err := cbor.DecOptions{IndefLength: cbor.IndefLengthForbidden, UTF8: cbor.UTF8RejectInvalid}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}()

func FuzzCheckDeterministic(f *testing.F) {
	for _, h := range []string{rfcClaimsA1, rfcSignedA3, rfcMacedA4, "fa45ad9c00", "c249010000000000000000", "a2020001 00"} {
		f.Add(mustHex(f, h))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		err := checkDeterministic(data)
		if err != nil && !errors.Is(err, cwt.ErrMalformed) {
			t.Fatalf("unclassified error: %v", err)
		}
		if err == nil {
			if werr := wellformed.Wellformed(data); werr != nil {
				t.Fatalf("accepted %x, which the CBOR library finds not well-formed: %v", data, werr)
			}
		}
	})
}
