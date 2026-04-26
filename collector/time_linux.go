//go:build linux

package collector

import (
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// bootOffsetNanos caches wall_now minus boot_now in nanoseconds so flow event
// timestamp conversion does not need a syscall per event
// the collector eviction loop refreshes it to keep up with NTP drift
var bootOffsetNanos atomic.Int64

func init() {
	refreshBootOffset()
}

// refreshBootOffset re-reads CLOCK_BOOTTIME and updates the cached offset
func refreshBootOffset() {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return
	}
	bootNs := int64(time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)*time.Nanosecond)
	bootOffsetNanos.Store(time.Now().UnixNano() - bootNs)
}

// bootTimeToWall converts a CLOCK_BOOTTIME nanosecond timestamp to wall time
// it falls back to time.Now() when the cached offset is unavailable
func bootTimeToWall(bootNs uint64) time.Time {
	offset := bootOffsetNanos.Load()
	if offset == 0 {
		return time.Now()
	}
	return time.Unix(0, offset+int64(bootNs))
}

// eventTime returns the wall-clock time for a flow event using the
// BPF CLOCK_BOOTTIME timestamp if available, falling back to time.Now()
func eventTime(ev FlowEvent) time.Time {
	if ev.Tstamp > 0 {
		return bootTimeToWall(ev.Tstamp)
	}
	return time.Now()
}
