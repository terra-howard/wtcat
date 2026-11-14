package cwt_test

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/terra-howard/wtcat/cwt"
)

func ptr(v int64) *int64 { return &v }

func TestCheckTimeBoundaries(t *testing.T) {
	const exp, nbf = 2_000_000_000, 1_999_000_000
	c := &cwt.Claims{Expiry: ptr(exp), NotBefore: ptr(nbf)}
	at := func(sec int64) time.Time { return time.Unix(sec, 0) }
	cases := []struct {
		name   string
		now    time.Time
		leeway time.Duration
		want   error
	}{
		{"one second before exp", at(exp - 1), 0, nil},
		{"half a second before exp", at(exp - 1).Add(500 * time.Millisecond), 0, nil},
		{"exactly at exp", at(exp), 0, cwt.ErrExpired},
		{"after exp", at(exp + 10), 0, cwt.ErrExpired},
		{"inside leeway after exp", at(exp + 59), time.Minute, nil},
		{"at the end of leeway after exp", at(exp + 60), time.Minute, cwt.ErrExpired},
		{"exactly at nbf", at(nbf), 0, nil},
		{"one second before nbf", at(nbf - 1), 0, cwt.ErrNotYetValid},
		{"at the start of leeway before nbf", at(nbf - 60), time.Minute, nil},
		{"before leeway before nbf", at(nbf - 61), time.Minute, cwt.ErrNotYetValid},
		{"sub-second leeway rounds down", at(exp), 900 * time.Millisecond, cwt.ErrExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := c.CheckTime(tc.now, tc.leeway); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCheckTimeAbsentClaimsAreNotChecked(t *testing.T) {
	if err := (&cwt.Claims{}).CheckTime(time.Unix(0, 0), 0); err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if err := (&cwt.Claims{IssuedAt: ptr(math.MaxInt64)}).CheckTime(time.Unix(0, 0), 0); err != nil {
		t.Fatalf("iat must not be checked: got %v", err)
	}
}

func TestCheckTimeDoesNotOverflow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	if err := (&cwt.Claims{Expiry: ptr(math.MaxInt64)}).CheckTime(now, time.Hour); err != nil {
		t.Fatalf("exp at the int64 limit plus leeway must not wrap into the past: %v", err)
	}
	if err := (&cwt.Claims{NotBefore: ptr(math.MinInt64)}).CheckTime(now, time.Hour); err != nil {
		t.Fatalf("nbf at the int64 limit minus leeway must not wrap into the future: %v", err)
	}
}

func TestCheckTimeRejectsNegativeLeeway(t *testing.T) {
	err := (&cwt.Claims{}).CheckTime(time.Unix(0, 0), -time.Second)
	if err == nil || errors.Is(err, cwt.ErrExpired) || errors.Is(err, cwt.ErrNotYetValid) {
		t.Fatalf("got %v, want a plain error for a negative leeway", err)
	}
}

func TestCheckTimeOnRFC8392Claims(t *testing.T) {
	// RFC 8392 A.1: nbf 1443944944, exp 1444064944.
	c := &cwt.Claims{Expiry: ptr(1444064944), NotBefore: ptr(1443944944), IssuedAt: ptr(1443944944)}
	if err := c.CheckTime(time.Unix(1443944944+1, 0), 0); err != nil {
		t.Fatalf("inside the window: %v", err)
	}
	if err := c.CheckTime(time.Unix(1444064944, 0), 0); !errors.Is(err, cwt.ErrExpired) {
		t.Fatalf("at exp: got %v, want ErrExpired", err)
	}
}
