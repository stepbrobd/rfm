//go:build ebpf_test

package probe

import (
	"net"
	"testing"
	"time"

	"ysun.co/rfm/testutil"
)

func TestLoad(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
}

func TestAttach(t *testing.T) {
	ns := testutil.NewNS(t)

	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		t.Fatal(err)
	}
}

func TestIfaceCounters(t *testing.T) {
	ns := testutil.NewNS(t)

	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// enable processing: set sample_rate > 0
	cfg := rfmRfmConfig{SampleRate: 1}
	if err := p.Config().Put(uint32(0), cfg); err != nil {
		t.Fatal(err)
	}

	if err := p.Attach(ns.Ifindex()); err != nil {
		t.Fatal(err)
	}

	// send an IPv4 TCP packet into rfm0 via rfm1
	pkt := testutil.EthIPv4TCP(
		net.IPv4(10, 0, 0, 1),
		net.IPv4(10, 0, 0, 2),
		12345, 80,
	)
	ns.SendRaw(t, pkt)

	// give the packet time to be processed
	time.Sleep(50 * time.Millisecond)

	// read iface stats
	key := rfmRfmIfaceKey{
		Ifindex: uint32(ns.Ifindex()),
		Dir:     0, // ingress (packet sent to rfm0 via rfm1)
		Proto:   4, // IPv4
	}

	var vals []rfmRfmIfaceValue
	if err := p.IfaceStats().Lookup(key, &vals); err != nil {
		t.Fatal(err)
	}

	// sum across CPUs
	var packets, bytes uint64
	for _, v := range vals {
		packets += v.Packets
		bytes += v.Bytes
	}

	if packets == 0 {
		t.Error("expected packets > 0")
	}
	if bytes == 0 {
		t.Error("expected bytes > 0")
	}
	t.Logf("packets=%d bytes=%d", packets, bytes)
}
