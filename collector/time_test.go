package collector

import (
	"testing"
	"time"
)

func TestSuspendOffsetReadsTheClocksAgainOnlyWhenTheSkewMoves(t *testing.T) {
	reads := 0
	s := suspendOffset{read: func() time.Duration { reads++; return time.Duration(reads) * time.Hour }}
	steps := []struct {
		skew, off time.Duration
		reads     int
	}{
		{0, time.Hour, 1},
		{999 * time.Microsecond, time.Hour, 1},
		{-999 * time.Microsecond, time.Hour, 1},
		// a resume moves the wall clock by the time the host spent suspended
		{2 * time.Hour, 2 * time.Hour, 2},
		{2*time.Hour + 500*time.Microsecond, 2 * time.Hour, 2},
		// a step back of the wall clock
		{time.Hour, 3 * time.Hour, 3},
	}
	for i, st := range steps {
		if got := s.at(st.skew); got != st.off || reads != st.reads {
			t.Fatalf("step %d: offset %v after %d reads, want %v after %d", i, got, reads, st.off, st.reads)
		}
	}
}

func TestClockSkewOfTwoReadingsIsNearZero(t *testing.T) {
	start := time.Now()
	time.Sleep(time.Millisecond)
	if d := clockSkew(start, time.Now()); d.Abs() >= time.Millisecond {
		t.Fatalf("skew %v between two readings a millisecond apart", d)
	}
}
