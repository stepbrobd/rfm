//go:build linux

package collector

import (
	"time"

	"golang.org/x/sys/unix"
)

// bootTimeToWall converts a CLOCK_BOOTTIME nanosecond timestamp to wall time
// it falls back to time.Now() if the clock read fails
func bootTimeToWall(bootNs uint64) time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Now()
	}
	bootNow := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)*time.Nanosecond
	wall := time.Now().Add(-bootNow)
	return wall.Add(time.Duration(bootNs))
}

// eventTime returns the wall-clock time for a flow event using the
// BPF CLOCK_BOOTTIME timestamp if available, falling back to time.Now()
func eventTime(ev FlowEvent) time.Time {
	if ev.Tstamp > 0 {
		return bootTimeToWall(ev.Tstamp)
	}
	return time.Now()
}
