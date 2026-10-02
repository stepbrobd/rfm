package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockPin holds an exclusive lock on the pin directory dir until release is
// called, so a second agent on the same pinned counters stops before it
// opens them, it would count the packets of an interface both attach twice
// and delete the counters of every interface it does not attach
// the lock is a flock on the directory, which the kernel drops when the
// process ends however it ends, and which every path that names the
// directory meets, from any network namespace
// release must stay reachable while the lock is held, it keeps the
// directory open
func lockPin(dir string) (release func(), err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create pin directory %q: %w", dir, err)
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open pin directory %q: %w", dir, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("pin path %q is in use by another agent", dir)
		}
		return nil, fmt.Errorf("lock pin directory %q: %w", dir, err)
	}
	return func() { f.Close() }, nil
}
