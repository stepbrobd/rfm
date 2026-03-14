//go:build !unix

package testutil

import "testing"

// RequireRoot skips on platforms without Unix-style effective uid support
func RequireRoot(t *testing.T) {
	t.Helper()
	t.Skip("root privilege checks are only supported on unix platforms")
}
