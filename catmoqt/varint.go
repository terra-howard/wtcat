package catmoqt

import "errors"

var errTruncated = errors.New("truncated variable-length integer")

// readVarint reads one of draft-ietf-moq-transport-22's variable-length integers from the front of b: the number of
// leading one bits of the first byte gives the length, 1 to 9 bytes, and the bits after the first zero, then any
// further bytes, hold the value. Longer encodings than needed are valid.
func readVarint(b []byte) (v uint64, rest []byte, err error) {
	if len(b) == 0 {
		return 0, nil, errTruncated
	}
	ones := 0
	for ones < 8 && b[0]&(0x80>>ones) != 0 {
		ones++
	}
	n := ones + 1
	if len(b) < n {
		return 0, nil, errTruncated
	}
	v = uint64(b[0] & (0xff >> n)) // empty for nine bytes, whose first byte holds only the length
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, b[n:], nil
}
