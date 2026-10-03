//go:build linux

package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"structs"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
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
	L2Len   uint8
	_       [7]uint8
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

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()
}

func TestLoadRefusesAZeroWakeupBatch(t *testing.T) {
	// the programs would never wake the reader of the flow events
	p, err := Load(Config{SampleRate: 1})
	if err == nil {
		p.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "wakeup batch") {
		t.Fatalf("load with a wakeup batch of 0 = %v, want it refused", err)
	}
}

func TestAttach(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
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

// addTun creates a tun device, whose frames carry no ethernet header
func addTun(t *testing.T, name string) netlink.Link {
	t.Helper()

	tun := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Mode:      netlink.TUNTAP_MODE_TUN,
		Flags:     netlink.TUNTAP_NO_PI,
	}
	if err := netlink.LinkAdd(tun); err != nil {
		t.Fatalf("add tun device: %v", err)
	}
	// the device is persistent and outlives its queue descriptors
	for _, f := range tun.Fds {
		f.Close()
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestAttachLinkTypes(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// loopback frames carry an ethernet header like veth frames
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Attach(lo.Attrs().Index); err != nil {
		skipIfUnsupported(t, err)
		t.Fatalf("attach loopback: %v", err)
	}

	// the programs would read the IP header of a tun frame as ethernet
	tun := addTun(t, "rfmtun0")
	err = p.Attach(tun.Attrs().Index)
	if !errors.Is(err, ErrUnsupportedLink) {
		t.Fatalf("attach tun = %v, want %v", err, ErrUnsupportedLink)
	}
	for _, ifindex := range p.Attached() {
		if ifindex == tun.Attrs().Index {
			t.Fatal("tun device attached")
		}
	}

	// a link that is gone reports ENODEV
	if err := p.Attach(1 << 30); !errors.Is(err, unix.ENODEV) {
		t.Fatalf("attach missing link = %v, want ENODEV", err)
	}
}

func TestIfaceCounters(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
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

func TestIfaceStatsErrorsCountFullMap(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	// one slot holds one key, every other key is refused
	p, err := Load(Config{WakeupBatch: 1, IfaceStatsSize: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	pkt := testutil.EthIPv4UDP(net.IPv4(10, 0, 8, 1), net.IPv4(10, 0, 8, 2), 8000, 53)
	ns.SendRaw(t, pkt)
	ns.SendRawOn(t, ns.Name(), pkt)

	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		n, err := p.IfaceStatsErrors()
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("no refused counter update counted")
		}
		return nil
	})
}

func TestIfaceCountersVLAN(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	// the kernel moves the tag of a received frame into the skb before the
	// ingress hook, the 4 tag bytes were on the wire all the same
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
	wantIfaceStats(t, p, key, 1, uint64(len(pkt)))
}

func TestIfaceCountersVLANEgress(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	// a vlan device hands its frames to the lower device with the tag held
	// in the skb, the tag goes into the frame after the egress hook ran
	vlan := addVLAN(t, ns, 42)
	pkt := testutil.EthIPv4TCP(net.IPv4(10, 0, 1, 3), net.IPv4(10, 0, 1, 4), 12001, 443)
	ns.SendRawOn(t, vlan, pkt)

	key := rfmRfmIfaceKey{
		Ifindex: uint32(ns.Ifindex()),
		Dir:     1,
		Proto:   4,
	}
	wantIfaceStats(t, p, key, 1, uint64(len(pkt)+testutil.VLANHdrLen))
}

func TestIfaceCountersVLANEgressGSO(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	// every wire packet of the gso skb gets the tag
	vlan := addVLAN(t, ns, 43)
	ns.SendGSO(t, vlan, gsoFrame(4400), gsoHdrLen, gsoSize)

	key := rfmRfmIfaceKey{
		Ifindex: uint32(ns.Ifindex()),
		Dir:     1,
		Proto:   4,
	}
	wantIfaceStats(t, p, key, gsoSegs, gsoWire+gsoSegs*testutil.VLANHdrLen)
}

// addVLAN creates a vlan device with id on the monitored interface and
// returns its name
func addVLAN(t *testing.T, ns *testutil.NS, id int) string {
	t.Helper()

	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Name: fmt.Sprintf("%s.%d", ns.Name(), id), ParentIndex: ns.Ifindex()},
		VlanId:    id,
	}
	if err := netlink.LinkAdd(vlan); err != nil {
		t.Fatalf("add vlan device: %v", err)
	}
	if err := netlink.LinkSetUp(vlan); err != nil {
		t.Fatal(err)
	}
	return vlan.Name
}

func TestIfaceCountersTruncatedVLANTag(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// the frame ends where its VLAN tag should start, the program cannot
	// parse it but must count it, as family other on the device of the
	// test run, which is loopback
	frame := testutil.Eth(
		net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02},
		testutil.EthP8021Q,
		nil,
	)
	if _, err := p.objs.RfmTcIngress.Run(&ebpf.RunOptions{Data: frame}); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	key := rfmRfmIfaceKey{Ifindex: uint32(lo.Attrs().Index), Dir: 0, Proto: 0}
	wantIfaceStats(t, p, key, 1, uint64(len(frame)))
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

	p, err := Load(Config{SampleRate: 1, WakeupBatch: 1})
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
	if ev.L2Len != testutil.EthHdrLen {
		t.Fatalf("l2_len = %d, want %d", ev.L2Len, testutil.EthHdrLen)
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
	// the tag is held in the skb by the time the ingress hook runs
	if ev.L2Len != testutil.EthHdrLen+testutil.VLANHdrLen {
		t.Fatalf("l2_len = %d, want %d", ev.L2Len, testutil.EthHdrLen+testutil.VLANHdrLen)
	}
	if ev.Len != uint32(len(pkt)) {
		t.Fatalf("len = %d, want %d", ev.Len, len(pkt))
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
	// the outer tag is held in the skb and the inner one stays in the frame
	if ev.L2Len != testutil.EthHdrLen+2*testutil.VLANHdrLen {
		t.Fatalf("l2_len = %d, want %d", ev.L2Len, testutil.EthHdrLen+2*testutil.VLANHdrLen)
	}
}

// v6 returns addr as the 16 address bytes of a flow event
func v6(addr string) [16]uint8 {
	return [16]uint8(net.ParseIP(addr).To16())
}

// readFlowEventFromSrc reads the first flow event of pkt, matched on its
// source address, so a wrong protocol or wrong ports still find the event
func readFlowEventFromSrc(t *testing.T, pkt []byte, src string) rfmRfmFlowEvent {
	t.Helper()

	return readFlowEvent(t, pkt, func(e rfmRfmFlowEvent) bool {
		return e.SrcAddr == v6(src)
	})
}

func TestFlowEventIPv6FirstFragmentKeepsPorts(t *testing.T) {
	testutil.RequireRoot(t)

	src := "fd00:3::1"
	payload := append(testutil.IPv6FragmentHeader(17, 0, true, 0x1234), testutil.UDP(5001, 53)...)
	pkt := testutil.EthIPv6(net.ParseIP(src), net.ParseIP("fd00:3::2"), testutil.IPProtoFragment, payload)

	ev := readFlowEventFromSrc(t, pkt, src)
	if ev.Proto != 17 {
		t.Fatalf("proto = %d, want 17 behind the fragment header", ev.Proto)
	}
	if ev.SrcPort != 5001 || ev.DstPort != 53 {
		t.Fatalf("ports = %d -> %d, want 5001 -> 53", ev.SrcPort, ev.DstPort)
	}
}

func TestFlowEventIPv6NonInitialFragmentZeroPorts(t *testing.T) {
	testutil.RequireRoot(t)

	// the bytes behind a later fragment look like ports but are payload
	src := "fd00:4::1"
	payload := append(testutil.IPv6FragmentHeader(17, 8, true, 0x1234), testutil.UDP(5001, 53)...)
	pkt := testutil.EthIPv6(net.ParseIP(src), net.ParseIP("fd00:4::2"), testutil.IPProtoFragment, payload)

	ev := readFlowEventFromSrc(t, pkt, src)
	if ev.Proto != 17 {
		t.Fatalf("proto = %d, want 17 like a later IPv4 fragment", ev.Proto)
	}
	if ev.SrcPort != 0 || ev.DstPort != 0 {
		t.Fatalf("ports = %d -> %d, want 0 -> 0", ev.SrcPort, ev.DstPort)
	}
}

func TestFlowEventIPv6ExtensionHeaderChain(t *testing.T) {
	testutil.RequireRoot(t)

	src := "fd00:5::1"
	var payload []byte
	payload = append(payload, testutil.IPv6Options(testutil.IPProtoDstOpts)...)
	payload = append(payload, testutil.IPv6Options(testutil.IPProtoRouting)...)
	payload = append(payload, testutil.IPv6Routing(testutil.IPProtoAH)...)
	payload = append(payload, testutil.IPv6AH(6)...)
	payload = append(payload, testutil.TCP(4500, 443)...)
	pkt := testutil.EthIPv6(net.ParseIP(src), net.ParseIP("fd00:5::2"), testutil.IPProtoHopOpts, payload)

	ev := readFlowEventFromSrc(t, pkt, src)
	if ev.Proto != 6 {
		t.Fatalf("proto = %d, want 6 behind hop-by-hop, destination options, routing and AH", ev.Proto)
	}
	if ev.SrcPort != 4500 || ev.DstPort != 443 {
		t.Fatalf("ports = %d -> %d, want 4500 -> 443", ev.SrcPort, ev.DstPort)
	}
}

func TestFlowEventGROIngressIPv6ExtensionHeader(t *testing.T) {
	testutil.RequireRoot(t)

	// the gso skb carries a destination options header in front of TCP,
	// which every wire packet repeats
	const (
		hdrLen = testutil.EthHdrLen + testutil.IPv6HdrLen + 8 + testutil.TCPHdrLen
		wire   = gsoSegs * (hdrLen + gsoSize)
	)
	src := "fd00:7::1"
	payload := append(testutil.IPv6Options(6), testutil.TCP(4600, 443)...)
	payload = append(payload, make([]byte, gsoPayload)...)
	frame := testutil.EthIPv6(net.ParseIP(src), net.ParseIP("fd00:7::2"), testutil.IPProtoDstOpts, payload)

	ev := readFlowEventFrom(t, func(ns *testutil.NS) {
		ns.SendGSO(t, "rfm1", frame, hdrLen, gsoSize)
	}, func(e rfmRfmFlowEvent) bool {
		return e.SrcAddr == v6(src) && e.Dir == 0
	})

	if ev.Segs != gsoSegs {
		t.Fatalf("segs = %d, want %d", ev.Segs, gsoSegs)
	}
	if ev.Len != wire {
		t.Fatalf("len = %d, want %d wire bytes", ev.Len, wire)
	}
	if ev.Proto != 6 {
		t.Fatalf("proto = %d, want 6", ev.Proto)
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

// wantIfaceStats waits for the counters of key to reach packets and then
// requires bytes
func wantIfaceStats(t *testing.T, p *Probe, key rfmRfmIfaceKey, packets, bytes uint64) {
	t.Helper()

	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if got, _ := ifaceStats(t, p, key); got < packets {
			return fmt.Errorf("packets = %d, want %d", got, packets)
		}
		return nil
	})
	gotPackets, gotBytes := ifaceStats(t, p, key)
	if gotPackets != packets || gotBytes != bytes {
		t.Fatalf("counters = %d packets %d bytes, want %d packets %d bytes", gotPackets, gotBytes, packets, bytes)
	}
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

	p, err := Load(Config{WakeupBatch: 1})
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

	p, err := Load(Config{WakeupBatch: 1})
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

// skbContext is struct __sk_buff up to gso_size, a test run takes the gso
// fields from it and refuses a context that sets a field it does not take
type skbContext struct {
	_       [36]uint32 // len to data_meta
	_       [2]uint64  // flow_keys and tstamp
	_       uint32     // wire_len
	GSOSegs uint32
	_       uint64 // sk
	GSOSize uint32
}

func TestGSOHeaderErrorsCountHeadersThatDoNotParse(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// a gso skb without a segment count, as a driver that does not verify
	// its gso frames hands it up
	run := func(frame []byte) {
		t.Helper()
		if _, err := p.objs.RfmTcIngress.Run(&ebpf.RunOptions{Data: frame, Context: skbContext{GSOSize: gsoSize}}); err != nil {
			skipIfUnsupported(t, err)
			t.Fatal(err)
		}
	}

	frame := testutil.EthIPv4TCPPayload(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 4700, 443, make([]byte, 2*gsoSize))
	run(frame)
	if n, err := p.GSOHeaderErrors(); err != nil || n != 0 {
		t.Fatalf("gso header errors = %d, %v, want none for headers that parse", n, err)
	}

	// an ihl of 4 is shorter than any ipv4 header, the skb counts as one
	// packet without the header bytes of the segments it stands for
	frame[testutil.EthHdrLen] = 0x44
	run(frame)
	if n, err := p.GSOHeaderErrors(); err != nil || n != 1 {
		t.Fatalf("gso header errors = %d, %v, want 1 for an ipv4 header that does not parse", n, err)
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

// countingProgram builds a sched_cls program that adds one to slot of counts
// for every packet and then hands the packet on, TCX_NEXT and TC_ACT_UNSPEC
// are both -1
func countingProgram(t *testing.T, counts *ebpf.Map, slot uint32) *ebpf.Program {
	t.Helper()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.StoreImm(asm.RFP, -4, int64(slot), asm.Word),
			asm.LoadMapPtr(asm.R1, counts.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "next"),
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.Mov.Imm(asm.R0, -1).WithSymbol("next"),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	t.Cleanup(func() { prog.Close() })
	return prog
}

func TestAttachOrder(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	// a foreign tcx program is attached on both hooks before rfm, the
	// counters must still run first on ingress and last on egress, and the
	// programs behind rfm must still see every packet, the foreign tcx
	// program on ingress and the tc filters of a clsact qdisc on both hooks
	const (
		tcxIngress = iota
		tcxEgress
		tcIngress
		tcEgress
	)
	counts, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 4,
	})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer counts.Close()

	others := map[ebpf.AttachType]*ebpf.Program{
		ebpf.AttachTCXIngress: countingProgram(t, counts, tcxIngress),
		ebpf.AttachTCXEgress:  countingProgram(t, counts, tcxEgress),
	}
	for at, prog := range others {
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: ns.Ifindex(),
			Program:   prog,
			Attach:    at,
		})
		if err != nil {
			skipIfUnsupported(t, err)
			t.Fatal(err)
		}
		defer l.Close()
	}

	clsact := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ns.Ifindex(),
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(clsact); err != nil {
		t.Fatalf("add clsact: %v", err)
	}
	for parent, slot := range map[uint32]uint32{netlink.HANDLE_MIN_INGRESS: tcIngress, netlink.HANDLE_MIN_EGRESS: tcEgress} {
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: ns.Ifindex(),
				Parent:    parent,
				Handle:    1,
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
			Fd:           countingProgram(t, counts, slot).FD(),
			Name:         "rfm-test",
			DirectAction: true,
		}
		if err := netlink.FilterAdd(filter); err != nil {
			t.Fatalf("add tc filter: %v", err)
		}
	}

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}

	progID := func(prog *ebpf.Program) ebpf.ProgramID {
		info, err := prog.Info()
		if err != nil {
			t.Fatal(err)
		}
		id, ok := info.ID()
		if !ok {
			t.Fatal("program id unavailable")
		}
		return id
	}
	otherID := map[ebpf.AttachType]ebpf.ProgramID{}
	for at, prog := range others {
		otherID[at] = progID(prog)
	}
	ingressID := progID(p.objs.RfmTcIngress)
	egressID := progID(p.objs.RfmTcEgress)

	order := func(at ebpf.AttachType) []ebpf.ProgramID {
		res, err := link.QueryPrograms(link.QueryOptions{Target: ns.Ifindex(), Attach: at})
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]ebpf.ProgramID, 0, len(res.Programs))
		for _, ap := range res.Programs {
			ids = append(ids, ap.ID)
		}
		return ids
	}

	if got, other := order(ebpf.AttachTCXIngress), otherID[ebpf.AttachTCXIngress]; len(got) != 2 || got[0] != ingressID || got[1] != other {
		t.Fatalf("ingress order = %v, want [rfm %d, other %d]", got, ingressID, other)
	}
	if got, other := order(ebpf.AttachTCXEgress), otherID[ebpf.AttachTCXEgress]; len(got) != 2 || got[0] != other || got[1] != egressID {
		t.Fatalf("egress order = %v, want [other %d, rfm %d]", got, other, egressID)
	}

	// rfm only observes, every program behind it must still run, the counts
	// start over so that background traffic from before the attach is gone
	names := []string{"tcx ingress", "tcx egress", "tc ingress", "tc egress"}
	for slot := range names {
		if err := counts.Put(uint32(slot), uint64(0)); err != nil {
			t.Fatal(err)
		}
	}
	pkt := testutil.EthIPv4UDP(net.IPv4(10, 0, 6, 1), net.IPv4(10, 0, 6, 2), 6000, 53)
	ns.SendRaw(t, pkt)
	ns.SendRawOn(t, ns.Name(), pkt)

	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		for slot, name := range names {
			var n uint64
			if err := counts.Lookup(uint32(slot), &n); err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("%s program saw no packets", name)
			}
		}
		return nil
	})
}

func TestSetSampleRate(t *testing.T) {
	testutil.RequireRoot(t)

	p, err := Load(Config{SampleRate: 100, WakeupBatch: 64})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.SetSampleRate(7); err != nil {
		t.Fatal(err)
	}
	rate, err := p.SampleRate()
	if err != nil {
		t.Fatal(err)
	}
	if rate != 7 {
		t.Fatalf("sample rate = %d, want 7", rate)
	}

	// the other config fields survive the update
	var cfg rfmRfmConfig
	if err := p.objs.RfmConfig.Lookup(uint32(0), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.WakeupBatch != 64 {
		t.Fatalf("wakeup batch = %d after the update, want 64", cfg.WakeupBatch)
	}

	if err := p.SetSampleRate(0); err == nil {
		t.Fatal("sample rate 0 must be rejected")
	}
}

func TestDetachDropsCounters(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	// attaching twice is a no-op
	if err := p.Attach(ns.Ifindex()); err != nil {
		t.Fatal(err)
	}
	if got := p.Attached(); len(got) != 1 || got[0] != ns.Ifindex() {
		t.Fatalf("attached = %v, want [%d]", got, ns.Ifindex())
	}

	ns.SendRaw(t, testutil.EthIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 1, 80))
	key := rfmRfmIfaceKey{Ifindex: uint32(ns.Ifindex()), Dir: 0, Proto: 4}
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if packets, _ := ifaceStats(t, p, key); packets == 0 {
			return fmt.Errorf("expected packets > 0")
		}
		return nil
	})

	if err := p.Detach(ns.Ifindex()); err != nil {
		t.Fatal(err)
	}
	if got := p.Attached(); len(got) != 0 {
		t.Fatalf("attached after detach = %v, want none", got)
	}
	if packets, _ := ifaceStats(t, p, key); packets != 0 {
		t.Fatalf("counters survived detach: %d packets", packets)
	}

	// no program left on the interface, traffic is not counted any more
	ns.SendRaw(t, testutil.EthIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 2, 80))
	time.Sleep(50 * time.Millisecond)
	if packets, _ := ifaceStats(t, p, key); packets != 0 {
		t.Fatalf("detached interface still counted: %d packets", packets)
	}

	// detaching again is a no-op
	if err := p.Detach(ns.Ifindex()); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedCountersSurviveReload(t *testing.T) {
	testutil.RequireRoot(t)

	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		t.Skipf("bpffs not mounted: %v", err)
	}
	dir := fmt.Sprintf("/sys/fs/bpf/rfm-test-%d", os.Getpid())
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1, PinPath: dir})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	if err := p.Attach(ns.Ifindex()); err != nil {
		skipIfUnsupported(t, err)
		p.Close()
		t.Fatal(err)
	}

	ns.SendRaw(t, testutil.EthIPv4TCP(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 3, 80))
	key := rfmRfmIfaceKey{Ifindex: uint32(ns.Ifindex()), Dir: 0, Proto: 4}
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if packets, _ := ifaceStats(t, p, key); packets == 0 {
			return fmt.Errorf("expected packets > 0")
		}
		return nil
	})
	before, _ := ifaceStats(t, p, key)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// a second load under the same pin path picks the counters up
	p2, err := Load(Config{WakeupBatch: 1, PinPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	after, _ := ifaceStats(t, p2, key)
	if after != before {
		t.Fatalf("packets after reload = %d, want %d from the pinned map", after, before)
	}

	// a map of another size is refused and the pin keeps its counters
	p2.Close()
	_, err = Load(Config{WakeupBatch: 1, PinPath: dir, IfaceStatsSize: 128})
	if !errors.Is(err, ebpf.ErrMapIncompatible) || !strings.Contains(err.Error(), "MaxEntries: 4096 changed to 128") ||
		!strings.Contains(err.Error(), "remove the pin file or reboot") {
		t.Fatalf("load with a map of another size = %v, want the pin refused", err)
	}
	p3, err := Load(Config{WakeupBatch: 1, PinPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer p3.Close()
	if got, _ := ifaceStats(t, p3, key); got != before {
		t.Fatalf("packets after a refused load = %d, want %d from the pinned map", got, before)
	}
}

// testWatch is a Watch running for a test
type testWatch struct {
	events chan LinkEvent
	done   chan error
	cancel context.CancelFunc
	err    error
	ended  bool
}

// startWatch runs Watch for the links named with prefix, the watcher needs a
// thread inside the test namespace of its own, the test goroutine keeps the
// one NewNS locked
// gate, when set, holds back the first event until it is closed
func startWatch(t *testing.T, p *Probe, ns *testutil.NS, prefix string, gate <-chan struct{}) *testWatch {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	w := &testWatch{
		events: make(chan LinkEvent, 1024),
		done:   make(chan error, 1),
		cancel: cancel,
	}
	go func() {
		// the thread goes back to the namespace it came from before it is
		// unlocked, one that cannot go back stays locked, and the runtime
		// does not hand a thread locked at goroutine exit to other
		// goroutines, it ends it or, for the main thread, parks it
		runtime.LockOSThread()
		orig, err := netns.Get()
		if err != nil {
			w.done <- err
			return
		}
		defer orig.Close()
		if err := netns.Set(ns.Handle()); err != nil {
			w.done <- err
			return
		}
		err = p.Watch(ctx, func(name string) bool { return strings.HasPrefix(name, prefix) }, func(ev LinkEvent) {
			if gate != nil {
				<-gate
			}
			w.events <- ev
		})
		if netns.Set(orig) == nil {
			runtime.UnlockOSThread()
		}
		w.done <- err
	}()
	t.Cleanup(func() { w.stop() })
	return w
}

// threadsIn lists the threads of the process other than the calling one
// that live in the network namespace ns
func threadsIn(t *testing.T, ns netns.NsHandle) []int {
	t.Helper()

	var want unix.Stat_t
	if err := unix.Fstat(int(ns), &want); err != nil {
		t.Fatal(err)
	}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	var tids []int
	for _, task := range tasks {
		var tid int
		if _, err := fmt.Sscan(task.Name(), &tid); err != nil || tid == unix.Gettid() {
			continue
		}
		var st unix.Stat_t
		// a thread that exited in the meantime has no namespace to compare
		if err := unix.Stat("/proc/self/task/"+task.Name()+"/ns/net", &st); err != nil {
			continue
		}
		if st.Dev == want.Dev && st.Ino == want.Ino {
			tids = append(tids, tid)
		}
	}
	return tids
}

// next waits for the next attach or detach
func (w *testWatch) next(t *testing.T) LinkEvent {
	t.Helper()

	select {
	case ev := <-w.events:
		return ev
	case err := <-w.done:
		w.ended, w.err = true, err
		t.Fatalf("watch stopped: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for a link event")
	}
	return LinkEvent{}
}

// expect waits for one event per name, all attaches or all detaches
func (w *testWatch) expect(t *testing.T, attached bool, names ...string) {
	t.Helper()

	want := map[string]bool{}
	for _, name := range names {
		want[name] = true
	}
	for range names {
		ev := w.next(t)
		if ev.Attached != attached || !want[ev.Name] {
			t.Fatalf("unexpected event %+v, want attached=%v for %v", ev, attached, names)
		}
		delete(want, ev.Name)
	}
}

// stop cancels the watcher and returns what Watch returned
func (w *testWatch) stop() error {
	w.cancel()
	if !w.ended {
		w.err, w.ended = <-w.done, true
	}
	return w.err
}

// addVeth creates a veth pair
func addVeth(t *testing.T, name, peer string) *netlink.Veth {
	t.Helper()

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: peer}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	return veth
}

// ifindexOf returns the index of the named link
func ifindexOf(t *testing.T, name string) int {
	t.Helper()

	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return l.Attrs().Index
}

// attachedSet returns the attached interfaces as a set
func attachedSet(p *Probe) map[int]bool {
	set := map[int]bool{}
	for _, ifindex := range p.Attached() {
		set[ifindex] = true
	}
	return set
}

// waitSubscribed waits until a socket in the namespace of the calling
// thread listens to link messages and returns its netlink port id
func waitSubscribed(t *testing.T) uint32 {
	t.Helper()

	var port uint32
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		raw, err := os.ReadFile("/proc/thread-self/net/netlink")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(raw), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 4 || f[1] != "0" {
				continue
			}
			var pid uint32
			var groups uint32
			if _, err := fmt.Sscan(f[2], &pid); err != nil {
				continue
			}
			if _, err := fmt.Sscanf(f[3], "%x", &groups); err != nil {
				continue
			}
			if groups&(1<<(unix.RTNLGRP_LINK-1)) != 0 {
				port = pid
				return nil
			}
		}
		return fmt.Errorf("no link subscription yet")
	})
	return port
}

func TestPinnedCountersRefuseIncompatibleFlags(t *testing.T) {
	testutil.RequireRoot(t)

	dir := pinDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// a pin of the right shape whose flags differ, as another build may
	// leave it, is refused like a pin of another size
	spec, err := loadRfm()
	if err != nil {
		t.Fatal(err)
	}
	stale := spec.Maps["rfm_iface_stats"].Copy()
	stale.Flags |= unix.BPF_F_NO_PREALLOC
	m, err := ebpf.NewMap(stale)
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Pin(pinPathFor(dir)); err != nil {
		t.Fatal(err)
	}

	_, err = Load(Config{WakeupBatch: 1, PinPath: dir})
	if !errors.Is(err, ebpf.ErrMapIncompatible) || !strings.Contains(err.Error(), "Flags") ||
		!strings.Contains(err.Error(), "remove the pin file or reboot") {
		t.Fatalf("load with a pin of other flags = %v, want the pin refused", err)
	}
	// the pin stays for the operator to remove
	pinned, err := ebpf.LoadPinnedMap(pinPathFor(dir), nil)
	if err != nil {
		t.Fatalf("pin after the refused load: %v", err)
	}
	defer pinned.Close()
	if flags := pinned.Flags(); flags&unix.BPF_F_NO_PREALLOC == 0 {
		t.Fatalf("pinned map flags = %#x, the pin was replaced", flags)
	}
}

func TestWatchFollowsInterfaces(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	w := startWatch(t, p, ns, "rfmw", nil)
	waitSubscribed(t)

	veth := addVeth(t, "rfmw0", "rfmw1")
	w.expect(t, true, "rfmw0", "rfmw1")
	if got := len(p.Attached()); got != 2 {
		t.Fatalf("attached count = %d, want 2", got)
	}

	// a matching link without an ethernet header is skipped, its events
	// would come before the ones of the veth pair created after it
	tun := addTun(t, "rfmwtun0")
	veth2 := addVeth(t, "rfmw2", "rfmw3")
	w.expect(t, true, "rfmw2", "rfmw3")
	if attachedSet(p)[tun.Attrs().Index] {
		t.Fatal("tun device attached")
	}
	if err := netlink.LinkDel(veth2); err != nil {
		t.Fatal(err)
	}
	w.expect(t, false, "rfmw2", "rfmw3")

	// an interface outside the pattern is ignored
	other := addVeth(t, "other0", "other1")
	defer netlink.LinkDel(other)

	if err := netlink.LinkDel(veth); err != nil {
		t.Fatal(err)
	}
	w.expect(t, false, "rfmw0", "rfmw1")
	if got := len(p.Attached()); got != 0 {
		t.Fatalf("attached count after delete = %d, want 0", got)
	}

	if err := w.stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("watch returned %v, want context.Canceled", err)
	}

	// the thread of the watcher must not go back to the scheduler while it
	// still lives in the test namespace, which is about to go away
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if tids := threadsIn(t, ns.Handle()); len(tids) > 0 {
			return fmt.Errorf("threads %v outside the test still live in its namespace", tids)
		}
		return nil
	})
}

func TestWatchReconcilesExistingLinks(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// a pair that exists before the watcher starts, and a pair attached by
	// hand that goes away while no watcher runs
	addVeth(t, "rfmw0", "rfmw1")
	stale := addVeth(t, "rfmw2", "rfmw3")
	for _, name := range []string{"rfmw2", "rfmw3"} {
		if err := p.Attach(ifindexOf(t, name)); err != nil {
			skipIfUnsupported(t, err)
			t.Fatal(err)
		}
	}
	if err := netlink.LinkDel(stale); err != nil {
		t.Fatal(err)
	}

	w := startWatch(t, p, ns, "rfmw", nil)
	w.expect(t, true, "rfmw0", "rfmw1")
	w.expect(t, false, "rfmw2", "rfmw3")

	want := map[int]bool{ifindexOf(t, "rfmw0"): true, ifindexOf(t, "rfmw1"): true}
	if got := attachedSet(p); len(got) != len(want) || !got[ifindexOf(t, "rfmw0")] || !got[ifindexOf(t, "rfmw1")] {
		t.Fatalf("attached = %v, want %v", got, want)
	}
	if state := p.WatchState(); !state.Running || !state.Synced || state.Resubscribes != 0 || state.Errors != 0 {
		t.Fatalf("watch state = %+v, want running and synced without errors", state)
	}

	w.stop()
	if state := p.WatchState(); state.Running || state.Synced {
		t.Fatalf("watch state after stop = %+v, want neither running nor synced", state)
	}
}

func TestWatchSurvivesForeignMessages(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	w := startWatch(t, p, ns, "rfmw", nil)
	port := waitSubscribed(t)

	// another process can send to the subscription, its message is not a
	// kernel one and the watcher must drop it and go on
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	msg := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], unix.RTM_NEWLINK)
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: port}); err != nil {
		t.Fatalf("send to the watcher: %v", err)
	}

	addVeth(t, "rfmw0", "rfmw1")
	w.expect(t, true, "rfmw0", "rfmw1")
	if state := p.WatchState(); state.Errors != 1 || state.Resubscribes != 0 || !state.Running {
		t.Fatalf("watch state = %+v, want one dropped message on a running subscription", state)
	}
}

// corruptLinkMessage has the watcher of p receive the first new link message
// about name with an attribute that runs past the message
func corruptLinkMessage(p *Probe, name string) {
	done := false
	p.mangle = func(typ uint16, data []byte) {
		if done || typ != unix.RTM_NEWLINK {
			return
		}
		if l, err := netlink.LinkDeserialize(nil, data); err != nil || l.Attrs().Name != name {
			return
		}
		binary.NativeEndian.PutUint16(data[unix.SizeofIfInfomsg:], 0xffff)
		done = true
	}
}

func TestWatchResubscribesOnALinkItCannotDecode(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// a link the watcher cannot read may need an attach, the dump of the
	// next subscription attaches it
	corruptLinkMessage(p, "rfmw0")
	w := startWatch(t, p, ns, "rfmw", nil)
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if !p.WatchState().Synced {
			return fmt.Errorf("watch not synced")
		}
		return nil
	})
	addVeth(t, "rfmw0", "zzp0")
	w.expect(t, true, "rfmw0")
	if state := p.WatchState(); state.Resubscribes != 1 || state.Errors != 0 || !strings.Contains(state.LastError, "decode link message") {
		t.Fatalf("watch state = %+v, want one resubscription for the link it could not decode", state)
	}
}

func TestLinkDumpGoesToTheKernelAlone(t *testing.T) {
	// as root the request stays in a namespace of its own, without root the
	// dump must work as well, a send to the link group needs CAP_NET_ADMIN
	if os.Geteuid() == 0 {
		testutil.NewNS(t)
	}

	// another link subscriber, as a second agent or a routing daemon
	other, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(other)
	if err := unix.Bind(other, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 << (unix.RTNLGRP_LINK - 1)}); err != nil {
		t.Fatal(err)
	}

	s, err := nl.Subscribe(unix.NETLINK_ROUTE, unix.RTNLGRP_LINK)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	port, err := s.GetPid()
	if err != nil {
		t.Fatal(err)
	}
	req, err := dumpLinks(s)
	if err != nil {
		t.Fatal(err)
	}

	// the dump comes back on the subscribed socket
	if err := s.SetReceiveTimeout(&unix.Timeval{Sec: 5}); err != nil {
		t.Fatal(err)
	}
	for done := false; !done; {
		msgs, from, err := s.Receive()
		if err != nil {
			t.Fatalf("receive the dump: %v", err)
		}
		for _, m := range msgs {
			done = done || from.Pid == nl.PidKernel && m.Header.Seq == req.Seq && m.Header.Type == unix.NLMSG_DONE
		}
	}

	// a copy of a request sent to the group lands on every other subscriber
	// before the send returns
	buf := make([]byte, 1<<16)
	for {
		_, from, err := unix.Recvfrom(other, buf, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if sa, ok := from.(*unix.SockaddrNetlink); ok && sa.Pid == port {
			t.Fatal("the link dump request reached another link subscriber")
		}
	}
}

func TestWatchResubscribesAfterOverflow(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// the smallest receive buffer the kernel allows overflows while the
	// watcher hangs in its first notification and a burst of links comes in
	p.rcvbuf = 1
	gate := make(chan struct{})
	w := startWatch(t, p, ns, "rfmw", gate)
	waitSubscribed(t)

	addVeth(t, "rfmw0", "rfmw1")
	const pairs = 100
	var names []string
	for i := range pairs {
		name, peer := fmt.Sprintf("rfmw%d", 2*i+2), fmt.Sprintf("rfmw%d", 2*i+3)
		addVeth(t, name, peer)
		names = append(names, name, peer)
	}
	close(gate)

	// the links of the burst are attached all the same
	testutil.Eventually(t, 5*time.Second, 50*time.Millisecond, func() error {
		select {
		case err := <-w.done:
			w.ended, w.err = true, err
			t.Fatalf("watch stopped: %v", err)
		default:
		}
		attached := attachedSet(p)
		for _, name := range names {
			if !attached[ifindexOf(t, name)] {
				return fmt.Errorf("%s not attached", name)
			}
		}
		return nil
	})
	if state := p.WatchState(); state.Resubscribes == 0 || !strings.Contains(state.LastError, "no buffer space") {
		t.Fatalf("watch state = %+v, want a resubscription after ENOBUFS", state)
	}
}

// pinDir returns a bpffs directory for the pinned counters of one test
func pinDir(t *testing.T) string {
	t.Helper()

	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		t.Skipf("bpffs not mounted: %v", err)
	}
	dir := fmt.Sprintf("/sys/fs/bpf/rfm-test-%d-%s", os.Getpid(), t.Name())
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// putIfaceStats stores packets for key on the first CPU
func putIfaceStats(t *testing.T, p *Probe, key rfmRfmIfaceKey, packets uint64) {
	t.Helper()

	vals := make([]rfmRfmIfaceValue, ebpf.MustPossibleCPU())
	vals[0] = rfmRfmIfaceValue{Packets: packets, Bytes: 100 * packets}
	if err := p.IfaceStats().Put(key, vals); err != nil {
		t.Fatal(err)
	}
}

func TestWatchPrunesPinnedCounters(t *testing.T) {
	testutil.RequireRoot(t)

	dir := pinDir(t)
	ns := testutil.NewNS(t)
	other := addVeth(t, "other0", "other1")

	// an earlier run counted rfm0 and other0, this run only matches rfm0
	p, err := Load(Config{WakeupBatch: 1, PinPath: dir})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	kept := rfmRfmIfaceKey{Ifindex: uint32(ns.Ifindex()), Dir: 0, Proto: 4}
	stale := rfmRfmIfaceKey{Ifindex: uint32(other.Attrs().Index), Dir: 0, Proto: 4}
	putIfaceStats(t, p, kept, 7)
	putIfaceStats(t, p, stale, 9)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	p, err = Load(Config{WakeupBatch: 1, PinPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	w := startWatch(t, p, ns, ns.Name(), nil)
	w.expect(t, true, ns.Name())
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if !p.WatchState().Synced {
			return fmt.Errorf("watch not synced")
		}
		return nil
	})

	if packets, _ := ifaceStats(t, p, kept); packets < 7 {
		t.Fatalf("counters of the attached interface = %d packets, want at least the 7 pinned", packets)
	}
	if packets, _ := ifaceStats(t, p, stale); packets != 0 {
		t.Fatalf("counters of an interface this run did not attach survived: %d packets", packets)
	}
}

func TestWatchRetriesAFailedPrune(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)
	other := addVeth(t, "other0", "other1")

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// counters of an interface this run does not attach, in a map that
	// refuses every delete from userspace
	stale := rfmRfmIfaceKey{Ifindex: uint32(other.Attrs().Index), Dir: 0, Proto: 4}
	putIfaceStats(t, p, stale, 9)
	if err := p.IfaceStats().Freeze(); err != nil {
		t.Fatal(err)
	}

	// the failed prune is counted, and the dump of the next subscription,
	// which a link the watcher cannot decode starts, tries it again
	corruptLinkMessage(p, "rfmw0")
	startWatch(t, p, ns, "rfmw", nil)
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if st := p.WatchState(); !st.Synced || st.PruneErrors != 1 {
			return fmt.Errorf("watch state = %+v, want a failed prune after the first dump", st)
		}
		return nil
	})
	addVeth(t, "rfmw0", "zzp0")
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if st := p.WatchState(); st.Resubscribes != 1 || st.PruneErrors != 2 {
			return fmt.Errorf("watch state = %+v, want a second failed prune after the next dump", st)
		}
		return nil
	})
	if packets, _ := ifaceStats(t, p, stale); packets != 9 {
		t.Fatalf("counters in the frozen map = %d packets, want the 9 put", packets)
	}
}

func TestWatchClearsCountersOfDeletedLinks(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	w := startWatch(t, p, ns, "rfmw", nil)
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if !p.WatchState().Synced {
			return fmt.Errorf("watch not synced")
		}
		return nil
	})

	// counters of a link this run never attached, as a pinned map from an
	// earlier run holds them, go when the link goes
	other := addVeth(t, "other0", "other1")
	key := rfmRfmIfaceKey{Ifindex: uint32(other.Attrs().Index), Dir: 1, Proto: 6}
	putIfaceStats(t, p, key, 3)
	if err := netlink.LinkDel(other); err != nil {
		t.Fatal(err)
	}

	// a matching pair after the delete orders the check behind it
	addVeth(t, "rfmw0", "rfmw1")
	w.expect(t, true, "rfmw0", "rfmw1")
	if packets, _ := ifaceStats(t, p, key); packets != 0 {
		t.Fatalf("counters of a deleted link survived: %d packets", packets)
	}
}

// passProgram builds a sched_cls program that hands every packet on, a tcx
// hook takes every program once
func passProgram(t *testing.T) *ebpf.Program {
	t.Helper()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, -1),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	t.Cleanup(func() { prog.Close() })
	return prog
}

// fillIngress attaches programs to the tcx ingress hook of ifindex until it
// takes no more and returns their links
func fillIngress(t *testing.T, ifindex int) []link.Link {
	t.Helper()

	var links []link.Link
	for {
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: ifindex,
			Program:   passProgram(t),
			Attach:    ebpf.AttachTCXIngress,
		})
		if errors.Is(err, unix.ERANGE) {
			return links
		}
		if err != nil {
			skipIfUnsupported(t, err)
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		links = append(links, l)
	}
}

func TestWatchRetriesAFailedAttach(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// full ingress hooks refuse the attach of links that are there, the
	// counters a pinned map holds for them must outlive the first dump
	addVeth(t, "rfmw0", "zzp0")
	gone := addVeth(t, "rfmw1", "zzp1")
	ifindex, goneIndex := ifindexOf(t, "rfmw0"), ifindexOf(t, "rfmw1")
	fillers := fillIngress(t, ifindex)
	fillIngress(t, goneIndex)
	key := rfmRfmIfaceKey{Ifindex: uint32(ifindex), Dir: 0, Proto: 4}
	goneKey := rfmRfmIfaceKey{Ifindex: uint32(goneIndex), Dir: 0, Proto: 4}
	putIfaceStats(t, p, key, 5)
	putIfaceStats(t, p, goneKey, 5)

	w := startWatch(t, p, ns, "rfmw", nil)
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if st := p.WatchState(); !st.Synced || st.AttachErrors < 2 {
			return fmt.Errorf("watch state = %+v, want both failed attaches counted by the first dump", st)
		}
		return nil
	})
	if got := p.Pending(); len(got) != 2 || !slices.Contains(got, ifindex) || !slices.Contains(got, goneIndex) {
		t.Fatalf("pending = %v, want %d and %d", got, ifindex, goneIndex)
	}
	for _, k := range []rfmRfmIfaceKey{key, goneKey} {
		if packets, _ := ifaceStats(t, p, k); packets != 5 {
			t.Fatalf("counters of ifindex %d waiting for its attach = %d packets, want the 5 pinned", k.Ifindex, packets)
		}
	}

	// a pending link that goes is forgotten with its counters
	if err := netlink.LinkDel(gone); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if got := p.Pending(); len(got) != 1 || got[0] != ifindex {
			return fmt.Errorf("pending = %v, want [%d]", got, ifindex)
		}
		if packets, _ := ifaceStats(t, p, goneKey); packets != 0 {
			return fmt.Errorf("counters of a deleted pending link = %d packets, want none", packets)
		}
		return nil
	})

	// no message about the link comes, a timer tries it again and counts
	// every try that fails
	testutil.Eventually(t, 5*time.Second, 10*time.Millisecond, func() error {
		if st := p.WatchState(); st.AttachErrors < 3 {
			return fmt.Errorf("watch state = %+v, want a failed try after the dump", st)
		}
		return nil
	})

	// a later try attaches it once the hook has room, however far the pause
	// between tries has grown
	if err := fillers[0].Close(); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, 10*time.Second, 10*time.Millisecond, func() error {
		if !attachedSet(p)[ifindex] {
			return fmt.Errorf("rfmw0 not attached")
		}
		return nil
	})
	w.expect(t, true, "rfmw0")
	if got := p.Pending(); len(got) != 0 {
		t.Fatalf("pending after the attach = %v, want none", got)
	}
	if packets, _ := ifaceStats(t, p, key); packets < 5 {
		t.Fatalf("counters after the attach = %d packets, want at least the 5 pinned", packets)
	}
}

func TestWatchKeepsAPortThatLeavesItsBridge(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{WakeupBatch: 1})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	br := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "zzbr0"}}
	if err := netlink.LinkAdd(br); err != nil {
		t.Fatal(err)
	}
	port := addVeth(t, "rfmw0", "zzp0")
	if err := netlink.LinkSetMaster(port, br); err != nil {
		t.Fatal(err)
	}
	w := startWatch(t, p, ns, "rfmw", nil)
	w.expect(t, true, "rfmw0")
	ifindex := ifindexOf(t, "rfmw0")
	key := rfmRfmIfaceKey{Ifindex: uint32(ifindex), Dir: 0, Proto: 4}
	putIfaceStats(t, p, key, 1000)

	// the bridge sends a delete message of its own family for a port that
	// leaves it, on a release and when the bridge goes, the port stays
	if err := netlink.LinkSetNoMaster(port); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetMaster(port, br); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkDel(br); err != nil {
		t.Fatal(err)
	}

	// a matching pair after the bridge changes orders the checks behind
	// their messages, a detach of the port would come first
	addVeth(t, "rfmw1", "zzp1")
	w.expect(t, true, "rfmw1")
	if !attachedSet(p)[ifindex] {
		t.Fatal("the port was detached when it left its bridge")
	}
	if packets, _ := ifaceStats(t, p, key); packets != 1000 {
		t.Fatalf("counters of the port after it left its bridge = %d packets, want the 1000 it had", packets)
	}
}
