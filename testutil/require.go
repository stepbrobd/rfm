package testutil

import (
	"os/exec"
	"testing"
)

// RequireCommand skips the test unless the named binary is available in PATH
func RequireCommand(t *testing.T, name string) string {
	t.Helper()

	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not available", name)
	}

	return path
}
