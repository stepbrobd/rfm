package testutil

import (
	"testing"
	"time"
)

// Eventually retries fn until it succeeds or the timeout expires
func Eventually(t *testing.T, timeout, interval time.Duration, fn func() error) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last error

	for {
		last = fn()
		if last == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s: %v", timeout, last)
		}
		time.Sleep(interval)
	}
}
