//go:build unix

package testutil

import (
	"os"
	"testing"
)

// RequireRoot skips the test unless it is running as root
func RequireRoot(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}
}
