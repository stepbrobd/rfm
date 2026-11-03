package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockPin holds a flock on dir until release, a second agent on the same pins would count twice and prune the first one's counters
// release must stay reachable while the lock is held, it keeps the directory open
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
