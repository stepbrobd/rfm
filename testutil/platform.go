package testutil

import (
	"net"
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

// LoopbackName returns the platform loopback interface name
// (lo on Linux, lo0 on macOS), skips the test if no loopback is found
func LoopbackName(t *testing.T) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	t.Skip("no loopback interface found")
	return ""
}
