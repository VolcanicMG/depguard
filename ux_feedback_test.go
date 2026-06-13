package main

import (
	"testing"
	"time"
)

func TestFmtRemaining(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "moments"},
		{-5 * time.Hour, "moments"},
		{30 * time.Minute, "~1h"},     // rounds up
		{90 * time.Minute, "~2h"},     // 1.5h -> 2h
		{12 * time.Hour, "~12h"},      //
		{24 * time.Hour, "~1d"},       // exactly a day
		{25 * time.Hour, "~2d"},       // just over -> rounds up
		{48 * time.Hour, "~2d"},       // exactly two days
		{13 * 24 * time.Hour, "~13d"}, //
		{13*24*time.Hour + 1, "~14d"}, // a hair over 13d -> 14d
	}
	for _, c := range cases {
		if got := fmtRemaining(c.d); got != c.want {
			t.Errorf("fmtRemaining(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
