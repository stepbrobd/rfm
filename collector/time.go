package collector

import "time"

// clockSkew is how far the wall clock moved against the monotonic one from start to now, two time.Now readings, which a resume from suspend or a step of the wall clock moves and a slew does not
func clockSkew(start, now time.Time) time.Duration {
	return time.Duration(now.UnixNano()-start.UnixNano()) - now.Sub(start)
}

// suspendOffset keeps the time the host spent suspended and reads the clocks again only when the skew moved by a millisecond, so a batch costs no syscall
type suspendOffset struct {
	read func() time.Duration
	skew time.Duration
	off  time.Duration
	ok   bool
}

// at returns the suspended time for a batch read at the given skew
func (s *suspendOffset) at(skew time.Duration) time.Duration {
	if !s.ok || (skew-s.skew).Abs() >= time.Millisecond {
		s.off, s.skew, s.ok = s.read(), skew, true
	}
	return s.off
}
