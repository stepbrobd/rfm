//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"ysun.co/rfm/testutil"
)

// shutdownListener shuts down the reading side of the tcp listener of this
// process on port, the kernel then fails every accept on it with EINVAL, an
// error that is not temporary
func shutdownListener(t *testing.T, port int) {
	t.Helper()

	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range fds {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if listening, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || listening == 0 {
			continue
		}
		var bound int
		switch sa, _ := unix.Getsockname(fd); sa := sa.(type) {
		case *unix.SockaddrInet4:
			bound = sa.Port
		case *unix.SockaddrInet6:
			bound = sa.Port
		}
		if bound != port {
			continue
		}
		if err := unix.Shutdown(fd, unix.SHUT_RD); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("no listener on port %d", port)
}

func TestRunAgentFailsWithAFailedBMPListener(t *testing.T) {
	lo := testutil.LoopbackName(t)
	port := freePort(t)
	cfgPath := writeTestConfig(t, fmt.Sprintf(`
[agent]
interfaces = [%q]

[agent.enrich.rib.bmp]
host = "127.0.0.1"
port = %d
`, lo, port))

	f := newFakeProbe()
	run := startAgent(t, cfgPath, agentDeps{loadProbe: f.load})
	run.metricsURL(t)

	// nothing cancels the run, a listener that stops on an accept error that
	// is not temporary ends it with an error that makes the agent exit non
	// zero for systemd to restart it
	shutdownListener(t, port)
	select {
	case err := <-run.done:
		run.done <- err
		if err == nil || !strings.Contains(err.Error(), "bmp listener") || !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("agent returned %v, want the failure of the bmp listener", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("agent still running after its bmp listener stopped")
	}
	if !f.closed {
		t.Fatal("probe not closed")
	}
}
