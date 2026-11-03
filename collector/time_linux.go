//go:build linux

package collector

import (
	"time"

	"golang.org/x/sys/unix"
)

// bootNow reads CLOCK_BOOTTIME, the clock of the event timestamps, 0 when the clock fails
func bootNow() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}
