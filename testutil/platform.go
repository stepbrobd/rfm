package testutil

import (
	"runtime"
	"testing"
)

// RequireLinux skips the test unless it is running on linux
func RequireLinux(t *testing.T) {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("requires linux")
	}
}
