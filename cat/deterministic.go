package cat

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/terra-howard/wtcat/cwt"
)

// maxDepth is the deepest nesting of arrays, maps and tags accepted, the same limit as the CBOR library's default.
const maxDepth = 32

func notDeterministic(format string, args ...any) error {
	return fmt.Errorf("%w: not deterministically encoded: "+format, append([]any{cwt.ErrMalformed}, args...)...)
}

// checkDeterministic reports whether data is exactly one CBOR data item, encoded as CTA-5007-B section 4.5
// requires: RFC 8949 Section 4.2.1's core deterministic encoding, except that map keys may come in any order, plus
// the first floating-point rule of Section 4.2.2 (integral values that fit in 64 bits are integers, not floats).
//
// It checks well-formedness as it goes (truncation, reserved values, invalid UTF-8) but not duplicate map keys,
// which the decoder rejects. Every failure wraps cwt.ErrMalformed.
func checkDeterministic(data []byte) error {
	end, err := checkItem(data, 0, 0)
	if err != nil {
		return err
	}
	if end != len(data) {
		return notDeterministic("%d bytes after the data item", len(data)-end)
	}
	return nil
}

// checkItem checks the data item starting at off and returns the offset just past it.
func checkItem(data []byte, off, depth int) (int, error) {
	if off >= len(data) {
		return 0, notDeterministic("truncated at byte %d", off)
	}
	major, info := majorType(data[off:]), data[off]&0x1f
	pos := off + 1
	var arg uint64
	switch {
	case info < 24:
		arg = uint64(info)
	case info <= 27:
		n := 1 << (info - 24) // 1, 2, 4 or 8 bytes
		if len(data)-pos < n {
			return 0, notDeterministic("truncated argument at byte %d", off)
		}
		arg = readUint(data[pos : pos+n])
		pos += n
		if major == majorSimple {
			return checkSimpleOrFloat(info, arg, pos, off)
		}
		if arg < minimumFor(n) {
			return 0, notDeterministic("argument %d at byte %d is not in its shortest form", arg, off)
		}
	case info == 31:
		return 0, notDeterministic("indefinite length or break at byte %d", off)
	default:
		return 0, notDeterministic("reserved additional information %d at byte %d", info, off)
	}

	remaining := uint64(len(data) - pos)
	switch major {
	case majorUnsigned, majorNegative:
		return pos, nil
	case majorBytes, majorText:
		if arg > remaining {
			return 0, notDeterministic("string at byte %d runs past the end", off)
		}
		end := pos + int(arg)
		if major == majorText && !utf8.Valid(data[pos:end]) {
			return 0, notDeterministic("invalid UTF-8 in the text string at byte %d", off)
		}
		return end, nil
	case majorArray, majorMap:
		items := arg
		if major == majorMap {
			if arg > remaining/2 {
				return 0, notDeterministic("map at byte %d runs past the end", off)
			}
			items = 2 * arg
		}
		if items > remaining {
			return 0, notDeterministic("array at byte %d runs past the end", off)
		}
		if depth >= maxDepth {
			return 0, notDeterministic("nested more than %d deep at byte %d", maxDepth, off)
		}
		var err error
		for i := uint64(0); i < items; i++ {
			if pos, err = checkItem(data, pos, depth+1); err != nil {
				return 0, err
			}
		}
		return pos, nil
	case majorTag:
		if depth >= maxDepth {
			return 0, notDeterministic("nested more than %d deep at byte %d", maxDepth, off)
		}
		end, err := checkItem(data, pos, depth+1)
		if err != nil {
			return 0, err
		}
		if arg == 2 || arg == 3 {
			if err := checkBignum(data[pos:end], off); err != nil {
				return 0, err
			}
		}
		return end, nil
	default: // majorSimple with info below 24: simple values 0 to 23, all well-formed
		return pos, nil
	}
}

func readUint(b []byte) uint64 {
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	default:
		return binary.BigEndian.Uint64(b)
	}
}

// minimumFor is the smallest argument that needs an n-byte encoding (RFC 8949 Section 4.2.1).
func minimumFor(n int) uint64 {
	switch n {
	case 1:
		return 24
	case 2:
		return 1 << 8
	case 4:
		return 1 << 16
	default:
		return 1 << 32
	}
}

// checkBignum applies RFC 8949 Section 3.4.3's preferred serialization: a bignum's byte string has no leading
// zero, and a value that fits in 64 bits is an integer of major type 0 or 1 instead.
func checkBignum(content []byte, off int) error {
	if len(content) == 0 || majorType(content) != majorBytes {
		return notDeterministic("bignum tag at byte %d does not enclose a byte string", off)
	}
	// The content is a well-formed byte string; skip its head to reach the value's bytes.
	headLen := 1
	if info := content[0] & 0x1f; info >= 24 {
		headLen += 1 << (info - 24)
	}
	value := content[headLen:]
	if len(value) <= 8 {
		return notDeterministic("bignum at byte %d fits in 64 bits", off)
	}
	if value[0] == 0 {
		return notDeterministic("bignum at byte %d has a leading zero", off)
	}
	return nil
}

// checkSimpleOrFloat checks a major type 7 item with a 1, 2, 4 or 8 byte argument.
func checkSimpleOrFloat(info byte, arg uint64, end, off int) (int, error) {
	var v float64
	switch info {
	case 24:
		if arg < 32 {
			return 0, notDeterministic("simple value %d at byte %d must use the one-byte form", arg, off)
		}
		return end, nil
	case 25:
		v = halfToFloat64(uint16(arg))
	case 26:
		if singleFitsHalf(uint32(arg)) {
			return 0, notDeterministic("single-precision float at byte %d fits in half precision", off)
		}
		v = float64(math.Float32frombits(uint32(arg)))
	case 27:
		if doubleFitsSingle(arg) {
			return 0, notDeterministic("double-precision float at byte %d fits in single precision", off)
		}
		v = math.Float64frombits(arg)
	}
	if v == math.Trunc(v) && v >= -(1<<64) && v < 1<<64 {
		return 0, notDeterministic("float at byte %d has an integral value, which must be encoded as an integer", off)
	}
	return end, nil
}

// halfToFloat64 converts an IEEE 754 half-precision value exactly.
func halfToFloat64(h uint16) float64 {
	exp := int(h>>10) & 0x1f
	mant := float64(h & 0x3ff)
	var v float64
	switch exp {
	case 0:
		v = math.Ldexp(mant, -24)
	case 31:
		if mant == 0 {
			v = math.Inf(1)
		} else {
			v = math.NaN()
		}
	default:
		v = math.Ldexp(mant+1024, exp-25)
	}
	if h&0x8000 != 0 {
		v = -v
	}
	return v
}

// singleFitsHalf reports whether a single-precision value, NaN payloads included, is exactly representable in half
// precision. RFC 8949 Section 4.1: a shorter NaN is preferred if padding its significand with zeros restores it.
func singleFitsHalf(b uint32) bool {
	exp := int(b>>23) & 0xff
	mant := b & 0x7fffff
	switch {
	case exp == 0xff: // infinity or NaN
		return mant&0x1fff == 0
	case exp == 0: // zero fits; a single-precision subnormal is far below half precision's smallest value
		return mant == 0
	}
	e := exp - 127
	switch {
	case e > 15:
		return false
	case e >= -14: // a half-precision normal number keeps 10 of the 23 significand bits
		return mant&0x1fff == 0
	case e >= -24: // a half-precision subnormal is a multiple of 2^-24
		sig := mant | 1<<23
		shift := uint(-(e + 1))
		return sig&(1<<shift-1) == 0
	default:
		return false
	}
}

// doubleFitsSingle reports whether a double-precision value, NaN payloads included, is exactly representable in
// single precision.
func doubleFitsSingle(b uint64) bool {
	if b>>52&0x7ff == 0x7ff { // infinity or NaN: the payload must survive dropping 29 bits
		return b&(1<<29-1) == 0
	}
	v := math.Float64frombits(b)
	return math.Float64bits(float64(float32(v))) == b
}
