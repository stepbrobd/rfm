//go:build linux

package probe

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"ysun.co/rfm/testutil"
)

func skipIfUnsupported(t *testing.T, err error) {
	t.Helper()

	if errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("not supported: %v", err)
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("requires additional linux capabilities: %v", err)
	}
}

func TestLoad(t *testing.T) {
	testutil.RequireRoot(t)

	p, err := Load()
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()
}

func TestAttach(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load()
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
}

func TestIfaceCounters(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load()
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// no config setup required: iface stats must work independently
	// of sampling configuration

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	// send an IPv4 TCP packet into rfm0 via rfm1
	pkt := testutil.EthIPv4TCP(
		net.IPv4(10, 0, 0, 1),
		net.IPv4(10, 0, 0, 2),
		12345, 80,
	)
	ns.SendRaw(t, pkt)

	// read iface stats
	key := rfmRfmIfaceKey{
		Ifindex: uint32(ns.Ifindex()),
		Dir:     0, // ingress (packet sent to rfm0 via rfm1)
		Proto:   4, // IPv4
	}

	var packets, bytes uint64
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		var vals []rfmRfmIfaceValue
		if err := p.IfaceStats().Lookup(key, &vals); err != nil {
			return err
		}

		packets, bytes = 0, 0
		for _, v := range vals {
			packets += v.Packets
			bytes += v.Bytes
		}

		if packets == 0 {
			return fmt.Errorf("expected packets > 0")
		}
		if bytes == 0 {
			return fmt.Errorf("expected bytes > 0")
		}

		return nil
	})

	t.Logf("packets=%d bytes=%d", packets, bytes)
}
