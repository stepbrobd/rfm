//go:build linux

package collector

import (
	"time"

	"golang.org/x/sys/unix"
)

// bootNow reads CLOCK_BOOTTIME, the clock of the flow times, 0 when the clock fails
func bootNow() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}

// suspended reads CLOCK_BOOTTIME less CLOCK_MONOTONIC, the time the host spent suspended, which turns the coarse monotonic stamp of an event into boot time, 0 when a clock fails
func suspended() time.Duration {
	var boot, mono unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot) != nil || unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono) != nil {
		return 0
	}
	// the readings are a few hundred ns apart, a suspend lasts far longer than the millisecond the offset is rounded to
	return max(time.Duration(boot.Nano()-mono.Nano()).Round(time.Millisecond), 0)
}
