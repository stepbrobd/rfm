//go:build linux

package probe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"structs"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"ysun.co/rfm/testutil"
)

// rfmRfmFlowEvent matches the BPF struct rfm_flow_event
// ring buffer maps do not generate Go types
// define it here
type rfmRfmFlowEvent struct {
	_       structs.HostLayout
	Tstamp  uint64
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	Segs    uint16
	SrcAddr [16]uint8
	DstAddr [16]uint8
	SrcPort uint16
	DstPort uint16
	Len     uint32
}

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

	p, err := Load(Config{})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()
}

func TestAttach(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{})
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

	p, err := Load(Config{})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// no config setup required
	// iface stats must work independently of sampling configuration

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
		Dir:     0, // ingress
		Proto:   4, // ipv4
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

func TestIfaceCountersVLAN(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	pkt := testutil.EthVLANIPv4TCP(
		net.IPv4(10, 0, 1, 1),
		net.IPv4(10, 0, 1, 2),
		12000, 443, 42,
	)
	ns.SendRaw(t, pkt)

	key := rfmRfmIfaceKey{
		Ifindex: uint32(ns.Ifindex()),
		Dir:     0,
		Proto:   4,
	}

	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		var vals []rfmRfmIfaceValue
		if err := p.IfaceStats().Lookup(key, &vals); err != nil {
			return err
		}

		var packets uint64
		for _, v := range vals {
			packets += v.Packets
		}

		if packets == 0 {
			return fmt.Errorf("expected vlan packets > 0")
		}

		return nil
	})
}

// readFlowEvent sets up a probe with sampling, attaches it, sends a packet
// and reads flow events from the ring buffer until match returns true
// this filters out background traffic like ICMPv6 neighbor solicitations
func readFlowEvent(t *testing.T, pkt []byte, match func(rfmRfmFlowEvent) bool) rfmRfmFlowEvent {
	t.Helper()

	return readFlowEventFrom(t, func(ns *testutil.NS) { ns.SendRaw(t, pkt) }, match)
}

// readFlowEventFrom is readFlowEvent with a caller supplied sender
func readFlowEventFrom(t *testing.T, send func(*testutil.NS), match func(rfmRfmFlowEvent) bool) rfmRfmFlowEvent {
	t.Helper()

	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	rd, err := ringbuf.NewReader(p.FlowEvents())
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	send(ns)

	deadline := time.Now().Add(time.Second)
	for {
		rd.SetDeadline(deadline)
		rec, err := rd.Read()
		if err != nil {
			t.Fatalf("read flow event: %v", err)
		}

		var ev rfmRfmFlowEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
			t.Fatalf("decode event: %v", err)
		}

		if ev.Ifindex != uint32(ns.Ifindex()) {
			continue
		}
		if match(ev) {
			return ev
		}
	}
}

func TestFlowEventIPv4TCP(t *testing.T) {
	testutil.RequireRoot(t)

	pkt := testutil.EthIPv4TCP(
		net.IPv4(10, 0, 0, 1),
		net.IPv4(10, 0, 0, 2),
		12345, 80,
	)

	ev := readFlowEvent(t, pkt, func(e rfmRfmFlowEvent) bool {
		return e.Proto == 6 && e.SrcPort == 12345
	})

	if ev.Dir != 0 {
		t.Fatalf("dir = %d, want 0 (ingress)", ev.Dir)
	}
	if ev.Proto != 6 {
		t.Fatalf("proto = %d, want 6 (TCP)", ev.Proto)
	}

	wantSrc := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1}
	if ev.SrcAddr != wantSrc {
		t.Fatalf("src_addr = %v, want %v", ev.SrcAddr, wantSrc)
	}

	wantDst := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2}
	if ev.DstAddr != wantDst {
		t.Fatalf("dst_addr = %v, want %v", ev.DstAddr, wantDst)
	}

	if ev.SrcPort != 12345 {
		t.Fatalf("src_port = %d, want 12345", ev.SrcPort)
	}
	if ev.DstPort != 80 {
		t.Fatalf("dst_port = %d, want 80", ev.DstPort)
	}
	if ev.Len == 0 {
		t.Fatal("len = 0, want > 0")
	}
}

func TestFlowEventIPv6TCP(t *testing.T) {
	testutil.RequireRoot(t)

	pkt := testutil.EthIPv6TCP(
		net.ParseIP("fd00::1"),
		net.ParseIP("fd00::2"),
		4000, 443,
	)

	ev := readFlowEvent(t, pkt, func(e rfmRfmFlowEvent) bool {
		return e.Proto == 6 && e.SrcPort == 4000
	})

	wantSrc := [16]uint8{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if ev.SrcAddr != wantSrc {
		t.Fatalf("src_addr = %v, want %v", ev.SrcAddr, wantSrc)
	}

	wantDst := [16]uint8{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	if ev.DstAddr != wantDst {
		t.Fatalf("dst_addr = %v, want %v", ev.DstAddr, wantDst)
	}

	if ev.SrcPort != 4000 {
		t.Fatalf("src_port = %d, want 4000", ev.SrcPort)
	}
	if ev.DstPort != 443 {
		t.Fatalf("dst_port = %d, want 443", ev.DstPort)
	}
}

func TestFlowEventIPv4Options(t *testing.T) {
	testutil.RequireRoot(t)

	// 4 NOP options give IHL=6 with a 24-byte header
	options := []byte{0x01, 0x01, 0x01, 0x01}
	pkt := testutil.EthIPv4TCPWithOptions(
		net.IPv4(10, 0, 0, 1),
		net.IPv4(10, 0, 0, 2),
		7777, 443,
		options,
	)

	ev := readFlowEvent(t, pkt, func(e rfmRfmFlowEvent) bool {
		return e.Proto == 6 && e.SrcPort == 7777
	})

	if ev.SrcPort != 7777 {
		t.Fatalf("src_port = %d, want 7777", ev.SrcPort)
	}
	if ev.DstPort != 443 {
		t.Fatalf("dst_port = %d, want 443", ev.DstPort)
	}
}

func TestFlowEventUDP(t *testing.T) {
	testutil.RequireRoot(t)

	pkt := testutil.EthIPv4UDP(
		net.IPv4(10, 0, 0, 1),
		net.IPv4(10, 0, 0, 2),
		5000, 53,
	)

	ev := readFlowEvent(t, pkt, func(e rfmRfmFlowEvent) bool {
		return e.Proto == 17 && e.SrcPort == 5000
	})

	if ev.DstPort != 53 {
		t.Fatalf("dst_port = %d, want 53", ev.DstPort)
	}
}

func TestFlowEventIPv4FirstFragmentKeepsPorts(t *testing.T) {
	testutil.RequireRoot(t)

	pkt := testutil.EthIPv4UDPFragment(
		net.IPv4(10, 0, 3, 1),
		net.IPv4(10, 0, 3, 2),
		0x1234,
		0,
		true,
		testutil.UDP(5001, 53),
	)

	ev := readFlowEvent(t, pkt, func(e rfmRfmFlowEvent) bool {
		return e.Proto == 17 && e.SrcPort == 5001
	})

	if ev.SrcPort != 5001 {
		t.Fatalf("src_port = %d, want 5001", ev.SrcPort)
	}
	if ev.DstPort != 53 {
		t.Fatalf("dst_port = %d, want 53", ev.DstPort)
	}
}

func TestFlowEventIPv4NonInitialFragmentZeroPorts(t *testing.T) {
	testutil.RequireRoot(t)

	pkt := testutil.EthIPv4UDPFragment(
		net.IPv4(10, 0, 4, 1),
		net.IPv4(10, 0, 4, 2),
		0x1234,
		8,
		true,
		[]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22},
	)

	ev := readFlowEvent(t, pkt, func(e rfmRfmFlowEvent) bool {
		wantSrc := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 4, 1}
		return e.Proto == 17 && e.SrcAddr == wantSrc && e.DstPort == 0
	})

	if ev.SrcPort != 0 {
		t.Fatalf("src_port = %d, want 0", ev.SrcPort)
	}
	if ev.DstPort != 0 {
		t.Fatalf("dst_port = %d, want 0", ev.DstPort)
	}
}

func TestFlowEventVLANIPv4TCP(t *testing.T) {
	testutil.RequireRoot(t)

	pkt := testutil.EthVLANIPv4TCP(
		net.IPv4(10, 0, 2, 1),
		net.IPv4(10, 0, 2, 2),
		33000, 8443, 123,
	)

	ev := readFlowEvent(t, pkt, func(e rfmRfmFlowEvent) bool {
		return e.Proto == 6 && e.SrcPort == 33000
	})

	wantSrc := [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 2, 1}
	if ev.SrcAddr != wantSrc {
		t.Fatalf("src_addr = %v, want %v", ev.SrcAddr, wantSrc)
	}
	if ev.DstPort != 8443 {
		t.Fatalf("dst_port = %d, want 8443", ev.DstPort)
	}
}

func TestFlowEventQinQIPv6UDP(t *testing.T) {
	testutil.RequireRoot(t)

	pkt := testutil.EthQinQIPv6UDP(
		net.ParseIP("fd00:1::1"),
		net.ParseIP("fd00:1::2"),
		5300, 5353, 10, 20,
	)

	ev := readFlowEvent(t, pkt, func(e rfmRfmFlowEvent) bool {
		return e.Proto == 17 && e.SrcPort == 5300
	})

	wantDst := [16]uint8{0xfd, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	if ev.DstAddr != wantDst {
		t.Fatalf("dst_addr = %v, want %v", ev.DstAddr, wantDst)
	}
	if ev.DstPort != 5353 {
		t.Fatalf("dst_port = %d, want 5353", ev.DstPort)
	}
}

// ifaceStats sums the per-CPU iface stats for key
func ifaceStats(t *testing.T, p *Probe, key rfmRfmIfaceKey) (packets, bytes uint64) {
	t.Helper()

	var vals []rfmRfmIfaceValue
	if err := p.IfaceStats().Lookup(key, &vals); err != nil {
		return 0, 0
	}
	for _, v := range vals {
		packets += v.Packets
		bytes += v.Bytes
	}
	return packets, bytes
}

// gsoFrame is a 5000 byte TCP payload split into 1000 byte segments
// on the wire that is 5 packets of 54 header bytes plus 1000 payload bytes
const (
	gsoPayload = 5000
	gsoSize    = 1000
	gsoHdrLen  = testutil.EthHdrLen + testutil.IPv4HdrLen + testutil.TCPHdrLen
	gsoSegs    = gsoPayload / gsoSize
	gsoWire    = gsoSegs * (gsoHdrLen + gsoSize)
)

func gsoFrame(srcPort uint16) []byte {
	return testutil.EthIPv4TCPPayload(
		net.IPv4(10, 0, 5, 1),
		net.IPv4(10, 0, 5, 2),
		srcPort, 443,
		make([]byte, gsoPayload),
	)
}

func TestIfaceCountersGSOEgress(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	// one gso skb leaves the monitored interface before segmentation
	ns.SendGSO(t, ns.Name(), gsoFrame(4100), gsoHdrLen, gsoSize)

	key := rfmRfmIfaceKey{
		Ifindex: uint32(ns.Ifindex()),
		Dir:     1,
		Proto:   4,
	}

	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		packets, _ := ifaceStats(t, p, key)
		if packets == 0 {
			return fmt.Errorf("expected egress packets > 0")
		}
		return nil
	})

	packets, bytes := ifaceStats(t, p, key)
	if packets != gsoSegs {
		t.Fatalf("egress packets = %d, want %d wire packets for one gso skb", packets, gsoSegs)
	}
	if bytes != gsoWire {
		t.Fatalf("egress bytes = %d, want %d wire bytes for one gso skb", bytes, gsoWire)
	}
}

func TestIfaceCountersGROIngress(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	// a gso skb sent from the peer arrives on the monitored end as one
	// ingress skb standing for several wire packets, like a gro merge
	ns.SendGSO(t, "rfm1", gsoFrame(4200), gsoHdrLen, gsoSize)

	key := rfmRfmIfaceKey{
		Ifindex: uint32(ns.Ifindex()),
		Dir:     0,
		Proto:   4,
	}

	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		packets, _ := ifaceStats(t, p, key)
		if packets == 0 {
			return fmt.Errorf("expected ingress packets > 0")
		}
		return nil
	})

	packets, bytes := ifaceStats(t, p, key)
	if packets != gsoSegs {
		t.Fatalf("ingress packets = %d, want %d wire packets for one gso skb", packets, gsoSegs)
	}
	if bytes != gsoWire {
		t.Fatalf("ingress bytes = %d, want %d wire bytes for one gso skb", bytes, gsoWire)
	}
}

func TestFlowEventGSOSegments(t *testing.T) {
	testutil.RequireRoot(t)

	ev := readFlowEventFrom(t, func(ns *testutil.NS) {
		ns.SendGSO(t, ns.Name(), gsoFrame(4300), gsoHdrLen, gsoSize)
	}, func(e rfmRfmFlowEvent) bool {
		return e.Proto == 6 && e.SrcPort == 4300 && e.Dir == 1
	})

	if ev.Segs != gsoSegs {
		t.Fatalf("segs = %d, want %d", ev.Segs, gsoSegs)
	}
	if ev.Len != gsoWire {
		t.Fatalf("len = %d, want %d wire bytes", ev.Len, gsoWire)
	}
}

func TestFlowEventPlainPacketOneSegment(t *testing.T) {
	testutil.RequireRoot(t)

	pkt := testutil.EthIPv4TCP(
		net.IPv4(10, 0, 0, 1),
		net.IPv4(10, 0, 0, 2),
		4400, 80,
	)

	ev := readFlowEvent(t, pkt, func(e rfmRfmFlowEvent) bool {
		return e.Proto == 6 && e.SrcPort == 4400
	})

	if ev.Segs != 1 {
		t.Fatalf("segs = %d, want 1", ev.Segs)
	}
	if ev.Len != uint32(len(pkt)) {
		t.Fatalf("len = %d, want %d", ev.Len, len(pkt))
	}
}
