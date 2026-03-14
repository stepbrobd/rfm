//go:build linux

package testutil

import (
	"errors"
	"syscall"
	"testing"
)

// SkipIfUnprivileged skips when a Linux-specific operation is blocked by missing capabilities
func SkipIfUnprivileged(t *testing.T, err error) {
	t.Helper()

	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("requires additional linux capabilities: %v", err)
	}
}
