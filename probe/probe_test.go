//go:build linux

package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/testutil"
)

func TestLoadRefusesAZeroSampleRate(t *testing.T) {
	p, err := Load(Config{WakeupBatch: 1})
	if err == nil {
		p.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "sample rate") {
		t.Fatalf("load with a sample rate of 0 = %v, want it refused", err)
	}
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

	// loopback frames carry an ethernet header like veth frames
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkLinkType(lo.Attrs()); err != nil {
		t.Fatalf("loopback refused: %v", err)
	}

	// the programs would read the IP header of a tun frame as ethernet
	tun := addTun(t, "rfmtun0")
	if err := checkLinkType(tun.Attrs()); !errors.Is(err, errUnsupportedLink) {
		t.Fatalf("tun = %v, want %v", err, errUnsupportedLink)
	}

	// a link that is gone reports ENODEV
	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.attach(1<<30, "gone"); !errors.Is(err, unix.ENODEV) {
		t.Fatalf("attach missing link = %v, want ENODEV", err)
	}
}

func TestIfaceStatsErrorsCountFullMap(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	// one entry holds one key, every other key is refused, and no counter
	// slot is free so the interface counts in the hash
	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, IfaceStatsSize: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	p.slots = newSlotAlloc(0, p.slots.maxIfindex)

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
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
	if _, err := p.ingress.Run(&ebpf.RunOptions{Data: frame}); err != nil {
		testutil.SkipIfUnprivileged(t, err)
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
func readFlowEvent(t *testing.T, pkt []byte, match func(collector.FlowEvent) bool) collector.FlowEvent {
	t.Helper()

	return readFlowEventFrom(t, func(ns *testutil.NS) { ns.SendRaw(t, pkt) }, match)
}

// readFlowEventFrom is readFlowEvent with a caller supplied sender
func readFlowEventFrom(t *testing.T, send func(*testutil.NS), match func(collector.FlowEvent) bool) collector.FlowEvent {
	t.Helper()

	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}

	rd := newFlowReader(t, p)

	send(ns)

	deadline := time.Now().Add(time.Second)
	for {
		raw, err := rd.read(deadline)
		if err != nil {
			t.Fatalf("read flow event: %v", err)
		}

		ev, err := collector.DecodeFlowEvent(raw)
		if err != nil {
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

	ev := readFlowEvent(t, pkt, func(e collector.FlowEvent) bool {
		return e.Proto == 6 && e.SrcPort == 12345
	})

	if ev.Dir != 0 {
		t.Fatalf("dir = %d, want 0 (ingress)", ev.Dir)
	}
	if ev.Proto != 6 {
		t.Fatalf("proto = %d, want 6 (TCP)", ev.Proto)
	}

	wantSrc := netip.MustParseAddr("::ffff:10.0.0.1")
	if ev.SrcAddr != wantSrc {
		t.Fatalf("src_addr = %v, want %v", ev.SrcAddr, wantSrc)
	}

	wantDst := netip.MustParseAddr("::ffff:10.0.0.2")
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

	ev := readFlowEvent(t, pkt, func(e collector.FlowEvent) bool {
		return e.Proto == 6 && e.SrcPort == 4000
	})

	wantSrc := netip.MustParseAddr("fd00::1")
	if ev.SrcAddr != wantSrc {
		t.Fatalf("src_addr = %v, want %v", ev.SrcAddr, wantSrc)
	}

	wantDst := netip.MustParseAddr("fd00::2")
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

	ev := readFlowEvent(t, pkt, func(e collector.FlowEvent) bool {
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

	ev := readFlowEvent(t, pkt, func(e collector.FlowEvent) bool {
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

	ev := readFlowEvent(t, pkt, func(e collector.FlowEvent) bool {
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

	ev := readFlowEvent(t, pkt, func(e collector.FlowEvent) bool {
		wantSrc := netip.MustParseAddr("::ffff:10.0.4.1")
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

	ev := readFlowEvent(t, pkt, func(e collector.FlowEvent) bool {
		return e.Proto == 6 && e.SrcPort == 33000
	})

	wantSrc := netip.MustParseAddr("::ffff:10.0.2.1")
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

	ev := readFlowEvent(t, pkt, func(e collector.FlowEvent) bool {
		return e.Proto == 17 && e.SrcPort == 5300
	})

	wantDst := netip.MustParseAddr("fd00:1::2")
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

// readFlowEventFromSrc reads the first flow event of pkt, matched on its
// source address, so a wrong protocol or wrong ports still find the event
func readFlowEventFromSrc(t *testing.T, pkt []byte, src string) collector.FlowEvent {
	t.Helper()

	return readFlowEvent(t, pkt, func(e collector.FlowEvent) bool {
		return e.SrcAddr == netip.MustParseAddr(src)
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

// longDstOpts builds a 256 byte destination options header, one PadN option
// filling it, which puts the transport header past RFM_DIRECT_OFF_MAX
func longDstOpts(next uint8) []byte {
	h := make([]byte, 256)
	h[0], h[1] = next, 31
	h[2], h[3] = 1, 252
	return h
}

func TestFlowEventIPv6LongExtensionHeader(t *testing.T) {
	testutil.RequireRoot(t)

	// the ports are read through the helper rather than straight from the
	// packet
	src := "fd00:8::1"
	payload := append(longDstOpts(17), testutil.UDP(4700, 53)...)
	pkt := testutil.EthIPv6(net.ParseIP(src), net.ParseIP("fd00:8::2"), testutil.IPProtoDstOpts, payload)

	ev := readFlowEventFromSrc(t, pkt, src)
	if ev.Proto != 17 || ev.SrcPort != 4700 || ev.DstPort != 53 {
		t.Fatalf("proto %d ports %d -> %d, want 17 and 4700 -> 53 behind a 256 byte header", ev.Proto, ev.SrcPort, ev.DstPort)
	}
}

func TestIngressGSOLongExtensionHeader(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// the tcp data offset is read through the helper rather than straight
	// from the packet, every wire packet repeats the 256 byte header
	const hdrLen = testutil.EthHdrLen + testutil.IPv6HdrLen + 256 + testutil.TCPHdrLen
	payload := append(longDstOpts(6), testutil.TCP(4800, 443)...)
	payload = append(payload, make([]byte, 2*gsoSize)...)
	frame := testutil.EthIPv6(net.ParseIP("fd00:9::1"), net.ParseIP("fd00:9::2"), testutil.IPProtoDstOpts, payload)
	ctx := skbContext{GSOSegs: 2, GSOSize: gsoSize}
	if _, err := p.ingress.Run(&ebpf.RunOptions{Data: frame, Context: ctx}); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	key := rfmRfmIfaceKey{Ifindex: uint32(lo.Attrs().Index), Dir: 0, Proto: 6}
	wantIfaceStats(t, p, key, 2, 2*(hdrLen+gsoSize))
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
	}, func(e collector.FlowEvent) bool {
		return e.SrcAddr == netip.MustParseAddr(src) && e.Dir == 0
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

// ifaceStats returns the counters Counters reports for key, over the slot
// and the hash
func ifaceStats(t *testing.T, p *Probe, key rfmRfmIfaceKey) (packets, bytes uint64) {
	t.Helper()

	counters, err := p.Counters()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range counters {
		if c.Ifindex == key.Ifindex && c.Dir == key.Dir && c.Proto == key.Proto {
			return c.Packets, c.Bytes
		}
	}
	return 0, 0
}

// hashStats sums the per-CPU hash entry of key alone
func hashStats(t *testing.T, p *Probe, key rfmRfmIfaceKey) (packets uint64) {
	t.Helper()

	var vals []rfmRfmIfaceValue
	if err := p.objs.RfmIfaceStats.Lookup(key, &vals); err != nil {
		return 0
	}
	for _, v := range vals {
		packets += v.Packets
	}
	return packets
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
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
	WireLen uint32
	GSOSegs uint32
	_       uint64 // sk
	GSOSize uint32
}

func TestGSOHeaderErrorsCountHeadersThatDoNotParse(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	run := func(frame []byte, ctx skbContext) {
		t.Helper()
		if _, err := p.ingress.Run(&ebpf.RunOptions{Data: frame, Context: ctx}); err != nil {
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
	}

	// a gso skb without a segment count, as an unverifying driver hands it up
	frame := testutil.EthIPv4TCPPayload(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 4700, 443, make([]byte, 2*gsoSize))
	run(frame, skbContext{GSOSize: gsoSize})
	if n, err := p.GSOHeaderErrors(); err != nil || n != 0 {
		t.Fatalf("gso header errors = %d, %v, want none for headers that parse", n, err)
	}

	// an ihl of 4 does not parse, the skb counts as one packet
	frame[testutil.EthHdrLen] = 0x44
	run(frame, skbContext{GSOSize: gsoSize})
	if n, err := p.GSOHeaderErrors(); err != nil || n != 1 {
		t.Fatalf("gso header errors = %d, %v, want 1 for an ipv4 header that does not parse", n, err)
	}

	// one segment adds no header bytes, its headers need no parse
	run(frame, skbContext{GSOSegs: 1, GSOSize: gsoSize})
	if n, err := p.GSOHeaderErrors(); err != nil || n != 1 {
		t.Fatalf("gso header errors = %d, %v, want still 1 after an skb of one segment", n, err)
	}
}

func TestIngressGSOTakesTheKernelWireLen(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	key := rfmRfmIfaceKey{Ifindex: uint32(lo.Attrs().Index), Dir: 0, Proto: 4}

	run := func(frame []byte, wire uint32) {
		t.Helper()
		ctx := skbContext{WireLen: wire, GSOSegs: gsoSegs, GSOSize: gsoSize}
		if _, err := p.ingress.Run(&ebpf.RunOptions{Data: frame, Context: ctx}); err != nil {
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
	}
	// wire_len from 6.19 counts every segment's headers but ethernet
	kernelWire := func(frame []byte) uint32 {
		segHdr := uint32(len(frame) - testutil.EthHdrLen - gsoPayload)
		return uint32(len(frame)-testutil.EthHdrLen) + (gsoSegs-1)*segHdr
	}
	// a wire_len of 0, as before 6.19, takes the header parse
	frame := gsoFrame(4900)
	run(frame, 0)
	wantIfaceStats(t, p, key, gsoSegs, gsoWire)
	run(frame, kernelWire(frame))
	wantIfaceStats(t, p, key, 2*gsoSegs, 2*gsoWire)

	// the inner tag of a qinq frame stays in the frame and in every segment
	tagged := slices.Concat(frame[:12], []byte{0x81, 0x00, 0, 42}, frame[12:])
	const taggedWire = gsoWire + gsoSegs*testutil.VLANHdrLen
	run(tagged, 0)
	wantIfaceStats(t, p, key, 3*gsoSegs, 2*gsoWire+taggedWire)
	run(tagged, kernelWire(tagged))
	wantIfaceStats(t, p, key, 4*gsoSegs, 2*gsoWire+2*taggedWire)

	// an ihl of 4 does not parse, and the kernel's wire_len needs no parse
	frame[testutil.EthHdrLen] = 0x44
	run(frame, kernelWire(frame))
	if n, err := p.GSOHeaderErrors(); err != nil || n != 0 {
		t.Fatalf("gso header errors = %d, %v, want none with the kernel's wire_len", n, err)
	}
	wantIfaceStats(t, p, key, 5*gsoSegs, 3*gsoWire+2*taggedWire)
	// the header parse counts it
	run(frame, 0)
	if n, err := p.GSOHeaderErrors(); err != nil || n != 1 {
		t.Fatalf("gso header errors = %d, %v, want 1 without the kernel's wire_len", n, err)
	}
}

func TestGSOHeaderErrorsSkipEgressWithASegmentCount(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	run := func(frame []byte, ctx skbContext) {
		t.Helper()
		if _, err := p.egress.Run(&ebpf.RunOptions{Data: frame, Context: ctx}); err != nil {
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
	}

	// an ihl of 4 does not parse, but egress takes its bytes from wire_len
	// and its packets from gso_segs, so the header size is not needed
	frame := testutil.EthIPv4TCPPayload(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 4800, 443, make([]byte, 2*gsoSize))
	frame[testutil.EthHdrLen] = 0x44
	wire := uint32(len(frame) + gsoHdrLen)
	run(frame, skbContext{WireLen: wire, GSOSegs: 2, GSOSize: gsoSize})
	if n, err := p.GSOHeaderErrors(); err != nil || n != 0 {
		t.Fatalf("gso header errors = %d, %v, want none for an egress skb with a segment count", n, err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	key := rfmRfmIfaceKey{Ifindex: uint32(lo.Attrs().Index), Dir: 1, Proto: 4}
	wantIfaceStats(t, p, key, 2, uint64(wire))

	// without a segment count the header size is needed for it
	run(frame, skbContext{WireLen: wire, GSOSize: gsoSize})
	if n, err := p.GSOHeaderErrors(); err != nil || n != 1 {
		t.Fatalf("gso header errors = %d, %v, want 1 for an egress skb without a segment count", n, err)
	}
}

func TestFlowEventGSOSegments(t *testing.T) {
	testutil.RequireRoot(t)

	ev := readFlowEventFrom(t, func(ns *testutil.NS) {
		ns.SendGSO(t, ns.Name(), gsoFrame(4300), gsoHdrLen, gsoSize)
	}, func(e collector.FlowEvent) bool {
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

	ev := readFlowEvent(t, pkt, func(e collector.FlowEvent) bool {
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
		testutil.SkipIfUnprivileged(t, err)
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
		testutil.SkipIfUnprivileged(t, err)
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
			testutil.SkipIfUnprivileged(t, err)
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
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
	ingressID := progID(p.ingress)
	egressID := progID(p.egress)

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
		testutil.SkipIfUnprivileged(t, err)
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
	if err := p.objs.RfmCfg.Get(&cfg); err != nil {
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	// attaching twice is a no-op
	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
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

	if _, _, err := p.detach(ns.Ifindex()); err != nil {
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
	if _, _, err := p.detach(ns.Ifindex()); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedCountersSurviveReload(t *testing.T) {
	testutil.RequireRoot(t)

	dir := pinDir(t)
	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
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
	p2, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
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
	_, err = Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir, IfaceStatsSize: 128})
	if !errors.Is(err, ebpf.ErrMapIncompatible) || !strings.Contains(err.Error(), "MaxEntries: 4096 changed to 128") ||
		!strings.Contains(err.Error(), "remove the pin file or reboot") {
		t.Fatalf("load with a map of another size = %v, want the pin refused", err)
	}
	p3, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
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

	// a pin of the right shape whose flags differ beyond the preallocation,
	// here a hash the programs could not write, is refused like a pin of
	// another size
	spec, err := loadRfm()
	if err != nil {
		t.Fatal(err)
	}
	stale := spec.Maps["rfm_iface_stats"].Copy()
	stale.Flags |= unix.BPF_F_RDONLY_PROG
	m, err := ebpf.NewMap(stale)
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Pin(filepath.Join(dir, pinStats)); err != nil {
		t.Fatal(err)
	}

	_, err = Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if !errors.Is(err, ebpf.ErrMapIncompatible) || !strings.Contains(err.Error(), "Flags") ||
		!strings.Contains(err.Error(), "remove the pin file or reboot") {
		t.Fatalf("load with a pin of other flags = %v, want the pin refused", err)
	}
	// the pin stays for the operator to remove
	pinned, err := ebpf.LoadPinnedMap(filepath.Join(dir, pinStats), nil)
	if err != nil {
		t.Fatalf("pin after the refused load: %v", err)
	}
	defer pinned.Close()
	if flags := pinned.Flags(); flags&unix.BPF_F_RDONLY_PROG == 0 {
		t.Fatalf("pinned map flags = %#x, the pin was replaced", flags)
	}
}

func TestPinnedCountersKeepTheirPreallocation(t *testing.T) {
	testutil.RequireRoot(t)

	dir := pinDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// a build before the hash was allocated on demand pinned it preallocated
	spec, err := loadRfm()
	if err != nil {
		t.Fatal(err)
	}
	old := spec.Maps[pinStats].Copy()
	old.Flags &^= unix.BPF_F_NO_PREALLOC
	m, err := ebpf.NewMap(old)
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Pin(filepath.Join(dir, pinStats)); err != nil {
		t.Fatal(err)
	}
	key := rfmRfmIfaceKey{Ifindex: 3, Dir: 0, Proto: 4}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	vals := make([]rfmRfmIfaceValue, ncpu)
	vals[0] = rfmRfmIfaceValue{Packets: 7, Bytes: 700}
	if err := m.Put(key, vals); err != nil {
		t.Fatal(err)
	}

	// the upgrade keeps that pin and its counters instead of failing the start
	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		t.Fatalf("load over a preallocated pin: %v", err)
	}
	defer p.Close()
	if flags := p.objs.RfmIfaceStats.Flags(); flags&unix.BPF_F_NO_PREALLOC != 0 {
		t.Fatalf("hash flags = %#x, want the preallocated pin", flags)
	}
	if packets := hashStats(t, p, key); packets != 7 {
		t.Fatalf("hash entry after the upgrade = %d packets, want the 7 pinned", packets)
	}
}

func TestCounterHashIsAllocatedOnDemand(t *testing.T) {
	testutil.RequireRoot(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	if flags := p.objs.RfmIfaceStats.Flags(); flags&unix.BPF_F_NO_PREALLOC == 0 {
		t.Fatalf("hash flags = %#x, want BPF_F_NO_PREALLOC", flags)
	}
}

func TestLoadSizesTheCounterArrayToTheSlots(t *testing.T) {
	testutil.RequireRoot(t)

	for _, tc := range []struct{ slots, want int }{{0, DefaultIfaceSlots}, {4, 4}, {MaxIfaceSlots, MaxIfaceSlots}} {
		p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, IfaceSlots: tc.slots})
		if err != nil {
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
		entries, free := p.objs.RfmIfaceArr.MaxEntries(), len(p.slots.used)
		p.Close()
		if entries != uint32(tc.want*2*ifaceFamilies) || free != tc.want {
			t.Fatalf("iface_slots %d: array of %d entries and %d slots, want %d slots", tc.slots, entries, free, tc.want)
		}
	}
	if _, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, IfaceSlots: MaxIfaceSlots + 1}); err == nil || !strings.Contains(err.Error(), "the programs index at most") {
		t.Fatalf("load with %d slots = %v, want it refused", MaxIfaceSlots+1, err)
	}
}

func TestPinnedCounterArrayKeepsItsSlotsUnlessSet(t *testing.T) {
	testutil.RequireRoot(t)

	dir := pinDir(t)
	// an earlier default of 256 slots left its pins
	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, IfaceSlots: MaxIfaceSlots, PinPath: dir})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// a load that sets no slots takes the pinned array as it is
	p, err = Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		t.Fatalf("load without slots over a 256 slot pin: %v", err)
	}
	entries, slots := p.objs.RfmIfaceArr.MaxEntries(), len(p.slots.used)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if entries != MaxIfaceSlots*2*ifaceFamilies || slots != MaxIfaceSlots {
		t.Fatalf("array of %d entries and %d slots, want the pinned %d slots", entries, slots, MaxIfaceSlots)
	}

	// a load that sets another count is refused like any other mismatch
	_, err = Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, IfaceSlots: 8, PinPath: dir})
	if !errors.Is(err, ebpf.ErrMapIncompatible) || !strings.Contains(err.Error(), "MaxEntries") {
		t.Fatalf("load with 8 slots over a 256 slot pin = %v, want the pin refused", err)
	}
}

func TestWatchFollowsInterfaces(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// a pair that exists before the watcher starts, and a pair attached by
	// hand that goes away while no watcher runs
	addVeth(t, "rfmw0", "rfmw1")
	stale := addVeth(t, "rfmw2", "rfmw3")
	for _, name := range []string{"rfmw2", "rfmw3"} {
		if _, err := p.attach(ifindexOf(t, name), name); err != nil {
			testutil.SkipIfUnprivileged(t, err)
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
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
	if err := p.objs.RfmIfaceStats.Put(key, vals); err != nil {
		t.Fatal(err)
	}
}

func TestWatchPrunesPinnedCounters(t *testing.T) {
	testutil.RequireRoot(t)

	dir := pinDir(t)
	ns := testutil.NewNS(t)
	other := addVeth(t, "other0", "other1")

	// an earlier run counted rfm0 and other0, this run only matches rfm0
	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	kept := rfmRfmIfaceKey{Ifindex: uint32(ns.Ifindex()), Dir: 0, Proto: 4}
	stale := rfmRfmIfaceKey{Ifindex: uint32(other.Attrs().Index), Dir: 0, Proto: 4}
	putIfaceStats(t, p, kept, 7)
	putIfaceStats(t, p, stale, 9)
	// other0 also counted in a slot, which the next load restores
	if _, err := p.attach(other.Attrs().Index, "other0"); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	p.mu.Lock()
	slot := p.slots.held()[stale.Ifindex]
	p.mu.Unlock()
	vals := make([]rfmRfmSlotValue, ebpf.MustPossibleCPU())
	vals[0].Packets = 4
	if err := p.objs.RfmIfaceArr.Put(slotIndex(slot, 0, 1), vals); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	p, err = Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
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
	p.mu.Lock()
	_, held := p.slots.held()[stale.Ifindex]
	p.mu.Unlock()
	if held {
		t.Fatal("the restored slot of an interface this run did not attach is still held")
	}
}

func TestWatchRetriesAFailedPrune(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)
	other := addVeth(t, "other0", "other1")

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// counters of an interface this run does not attach, in a map that
	// refuses every delete from userspace
	stale := rfmRfmIfaceKey{Ifindex: uint32(other.Attrs().Index), Dir: 0, Proto: 4}
	putIfaceStats(t, p, stale, 9)
	if err := p.objs.RfmIfaceStats.Freeze(); err != nil {
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

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
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
		testutil.SkipIfUnprivileged(t, err)
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
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		links = append(links, l)
	}
}

func TestWatchRetriesAFailedAttach(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
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

func TestWatchForgetsALinkRenamedAway(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// rfmw1 stays pending while its full ingress hook refuses the attach
	addVeth(t, "rfmw0", "zzp0")
	addVeth(t, "rfmw1", "zzp1")
	attached, pending := ifindexOf(t, "rfmw0"), ifindexOf(t, "rfmw1")
	fillers := fillIngress(t, pending)
	w := startWatch(t, p, ns, "rfmw", nil)
	w.expect(t, true, "rfmw0")
	testutil.Eventually(t, time.Second, 10*time.Millisecond, func() error {
		if got := p.Pending(); len(got) != 1 || got[0] != pending {
			return fmt.Errorf("pending = %v, want [%d]", got, pending)
		}
		return nil
	})

	for _, ifindex := range []int{attached, pending} {
		l, err := netlink.LinkByIndex(ifindex)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetName(l, fmt.Sprintf("zzr%d", ifindex)); err != nil {
			t.Fatal(err)
		}
	}
	w.expect(t, false, "rfmw0")

	// the hook has room again, and a matching pair after the renames orders the checks behind their messages
	if err := fillers[0].Close(); err != nil {
		t.Fatal(err)
	}
	addVeth(t, "rfmw2", "zzp2")
	w.expect(t, true, "rfmw2")
	if got := p.Pending(); len(got) != 0 {
		t.Fatalf("pending after the rename = %v, want none", got)
	}
	p.mu.Lock()
	held := p.slots.held()
	p.mu.Unlock()
	for _, ifindex := range []int{attached, pending} {
		if attachedSet(p)[ifindex] {
			t.Fatalf("ifindex %d still attached after its rename", ifindex)
		}
		if _, ok := held[uint32(ifindex)]; ok {
			t.Fatalf("ifindex %d keeps its slot after its rename", ifindex)
		}
	}
}

func TestAttachLinkReleasesTheSlotOfAGoneLink(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	veth := addVeth(t, "rfmw0", "zzp0")
	ifindex := ifindexOf(t, "rfmw0")
	if err := netlink.LinkDel(veth); err != nil {
		t.Fatal(err)
	}
	p.attachLink(ifindex, "rfmw0", func(LinkEvent) {})
	p.mu.Lock()
	_, held := p.slots.held()[uint32(ifindex)]
	p.mu.Unlock()
	if held {
		t.Fatal("a link gone at its attach keeps its slot")
	}
}

func TestWatchKeepsAPortThatLeavesItsBridge(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
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

func TestIfaceCountersUseSlot(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	pkt := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9000, 53)
	ns.SendRaw(t, pkt)

	key := rfmRfmIfaceKey{Ifindex: uint32(ns.Ifindex()), Dir: 0, Proto: 4}
	wantIfaceStats(t, p, key, 1, uint64(len(pkt)))
	// a slotted interface leaves the hash alone
	if packets := hashStats(t, p, key); packets != 0 {
		t.Fatalf("hash entry of a slotted interface = %d packets, want none", packets)
	}
}

func TestIfaceCountersFallBackToHash(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// every slot taken, the interface counts in the hash as before the slots
	p.slots = newSlotAlloc(0, p.slots.maxIfindex)
	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	pkt := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9001, 53)
	ns.SendRaw(t, pkt)

	key := rfmRfmIfaceKey{Ifindex: uint32(ns.Ifindex()), Dir: 0, Proto: 4}
	wantIfaceStats(t, p, key, 1, uint64(len(pkt)))
	if packets := hashStats(t, p, key); packets != 1 {
		t.Fatalf("hash entry of an interface without a slot = %d packets, want 1", packets)
	}
}

func TestIfaceCountersDetachZeroesSlot(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	key := rfmRfmIfaceKey{Ifindex: uint32(ns.Ifindex()), Dir: 0, Proto: 4}
	pkt := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9002, 53)
	for range 2 {
		// the slot a detach frees comes back zeroed on the next attach
		if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
		ns.SendRaw(t, pkt)
		wantIfaceStats(t, p, key, 1, uint64(len(pkt)))
		if _, _, err := p.detach(ns.Ifindex()); err != nil {
			t.Fatal(err)
		}
		if packets, _ := ifaceStats(t, p, key); packets != 0 {
			t.Fatalf("counters after detach = %d packets, want none", packets)
		}
	}
}

func TestPinnedCountersUpgradeFromHash(t *testing.T) {
	testutil.RequireRoot(t)

	dir := pinDir(t)
	ns := testutil.NewNS(t)

	// a build without slots left its counters in the pinned hash alone
	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	key := rfmRfmIfaceKey{Ifindex: uint32(ns.Ifindex()), Dir: 0, Proto: 4}
	putIfaceStats(t, p, key, 7)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{pinSlot, pinArr} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	// the upgrade counts new traffic in a slot and reports both
	p, err = Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	pkt := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9003, 53)
	ns.SendRaw(t, pkt)
	wantIfaceStats(t, p, key, 8, 700+uint64(len(pkt)))
	if packets := hashStats(t, p, key); packets != 7 {
		t.Fatalf("hash entry after the upgrade = %d packets, want the 7 pinned", packets)
	}
}

func TestPinnedCountersDropALoneSlotPin(t *testing.T) {
	testutil.RequireRoot(t)

	dir := pinDir(t)
	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		p.Close()
		t.Fatal(err)
	}
	pkt := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9004, 53)
	ns.SendRaw(t, pkt)
	key := rfmRfmIfaceKey{Ifindex: uint32(ns.Ifindex()), Dir: 0, Proto: 4}
	wantIfaceStats(t, p, key, 1, uint64(len(pkt)))
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// a start that stopped between the two pins leaves the slot map alone,
	// it names slots of a counter array that is gone
	if err := os.Remove(filepath.Join(dir, pinArr)); err != nil {
		t.Fatal(err)
	}
	p, err = Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		t.Fatalf("load with a lone slot pin: %v", err)
	}
	defer p.Close()
	if packets, _ := ifaceStats(t, p, key); packets != 0 {
		t.Fatalf("counters after the lone pin was dropped = %d packets, want none", packets)
	}
	for _, name := range []string{pinSlot, pinArr} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("pin %s after the load: %v", name, err)
		}
	}

	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		t.Fatal(err)
	}
	ns.SendRaw(t, pkt)
	wantIfaceStats(t, p, key, 1, uint64(len(pkt)))
}

// loopbackSamples runs the ingress program n times on an IPv4 frame, which a
// test run hands in on loopback, and returns how many runs it sampled, the
// events in the ring buffer plus the ones the ring dropped
func loopbackSamples(t *testing.T, p *Probe, n uint32) int {
	t.Helper()

	rd := newFlowReader(t, p)

	before := flowDrops(t, p)
	frame := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9100, 53)
	if _, err := p.ingress.Run(&ebpf.RunOptions{Data: frame, Repeat: n}); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	// the stage programs write or drop what they staged by the flush of each stage
	for cpu := range p.FlowRings() {
		waitStageIdle(t, p, cpu)
	}
	samples := int(flowDrops(t, p) - before)
	for {
		raw, err := rd.read(time.Now())
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return samples
		} else if err != nil {
			t.Fatal(err)
		}
		samples += len(raw) / eventSize
	}
}

// flowDrops returns the events the rings of every CPU refused
func flowDrops(t *testing.T, p *Probe) (sum uint64) {
	t.Helper()

	var vals []uint64
	if err := p.FlowDrops().Lookup(uint32(0), &vals); err != nil {
		t.Fatal(err)
	}
	for _, v := range vals {
		sum += v
	}
	return sum
}

// flowReader reads the event rings of every CPU, the ring a record lands in
// is the one of the CPU the program ran on
type flowReader struct {
	rds []*ringbuf.Reader
}

func newFlowReader(t *testing.T, p *Probe) *flowReader {
	t.Helper()

	var fr flowReader
	for _, ring := range p.FlowRings() {
		rd, err := ringbuf.NewReader(ring)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rd.Close() })
		fr.rds = append(fr.rds, rd)
	}
	return &fr
}

// read returns the next record of any ring, waiting for one until deadline
func (fr *flowReader) read(deadline time.Time) ([]byte, error) {
	for {
		for _, rd := range fr.rds {
			if rd.AvailableBytes() == 0 {
				continue
			}
			rd.SetDeadline(time.Now())
			rec, err := rd.Read()
			if err == nil {
				return rec.RawSample, nil
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, err
			}
		}
		if time.Now().After(deadline) {
			return nil, os.ErrDeadlineExceeded
		}
		time.Sleep(time.Millisecond)
	}
}

// pinOneCPU keeps the test on one CPU until it ends and returns it, test runs
// count, stage and write their events on the CPU they run on
func pinOneCPU(t *testing.T) int {
	t.Helper()

	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	var set, one unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		t.Fatal(err)
	}
	cpu := 0
	for !set.IsSet(cpu) {
		cpu++
	}
	one.Set(cpu)
	if err := unix.SchedSetaffinity(0, &one); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.SchedSetaffinity(0, &set) })
	return cpu
}

// slotLoopback gives loopback a counter slot, as Attach gives one to an
// interface it attaches
func slotLoopback(t *testing.T, p *Probe) {
	t.Helper()

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.assignSlot(lo.Attrs().Index); err != nil {
		t.Fatal(err)
	}
}

func TestSlotSamplingKeepsTheRate(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 10, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	slotLoopback(t, p)

	// gaps uniform from 1 to 19 put 2000 samples in 20000 packets with a
	// standard deviation near 25
	if got := loopbackSamples(t, p, 20000); got < 1800 || got > 2200 {
		t.Fatalf("samples of 20000 packets at 1 in 10 = %d, want 2000 within 200", got)
	}
}

func TestSlotSamplingFollowsARateChange(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	slotLoopback(t, p)

	// the first packet draws a gap of up to 2^31 packets
	if got := loopbackSamples(t, p, 1); got != 0 {
		t.Fatalf("samples at 1 in 2^30 = %d, want none", got)
	}
	// a new rate draws again at the next packet instead of finishing the gap
	if err := p.SetSampleRate(1); err != nil {
		t.Fatal(err)
	}
	if got := loopbackSamples(t, p, 5); got != 5 {
		t.Fatalf("samples of 5 packets after the rate went to 1 = %d, want 5", got)
	}
}

func TestPinnedSlotSamplingRedrawsOnLoad(t *testing.T) {
	testutil.RequireRoot(t)

	dir := pinDir(t)
	testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	slotLoopback(t, p)
	if got := loopbackSamples(t, p, 1); got != 0 {
		p.Close()
		t.Fatalf("samples at 1 in 2^30 = %d, want none", got)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}

	// the pinned slot keeps its gap, the next load draws it again at its
	// own rate
	p, err = Load(Config{SampleRate: 1, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if got := loopbackSamples(t, p, 5); got != 5 {
		t.Fatalf("samples of 5 packets after a load at 1 in 1 = %d, want 5", got)
	}
}

func TestWakeupCountsDownTheBatch(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	// one CPU keeps each countdown in one entry
	pinOneCPU(t)

	p, err := Load(Config{SampleRate: 1, WakeupBatch: 4})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// the first event wakes the reader and every fourth after it
	countDown := func(m *ebpf.Map, key uint32) {
		t.Helper()
		for i, want := range []uint32{4, 3, 2, 1, 4, 3} {
			if got := loopbackSamples(t, p, 1); got != 1 {
				t.Fatalf("event %d: samples = %d, want 1", i+1, got)
			}
			var vals []rfmRfmSlotValue
			if err := m.Lookup(key, &vals); err != nil {
				t.Fatal(err)
			}
			var left uint32
			for _, v := range vals {
				left += v.Wake
			}
			if left != want {
				t.Fatalf("after event %d the entry waits %d events to wake, want %d", i+1, left, want)
			}
		}
	}

	// loopback without a slot counts down in the draw entry of the CPU
	countDown(p.objs.RfmCpuDraw, 0)

	slotLoopback(t, p)
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	slot := p.slots.held()[uint32(lo.Attrs().Index)]
	p.mu.Unlock()
	countDown(p.objs.RfmIfaceArr, slotIndex(slot, 0, 1))
}

func TestFlowEventWritesEveryByte(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	// a ring of one page holds 64 records of 64 bytes, one CPU puts every
	// record in its ring
	pinOneCPU(t)
	p, err := Load(Config{SampleRate: 1, WakeupBatch: 1, RingBufSize: 4096})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	rd := newFlowReader(t, p)

	emit := func(frame []byte) []byte {
		t.Helper()
		if _, err := p.ingress.Run(&ebpf.RunOptions{Data: frame}); err != nil {
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
		raw, err := rd.read(time.Now().Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	// records with every address byte set fill the whole ring, then IPv4
	// records written over them must leave the zero prefix of the mapped
	// addresses
	ones := net.IP(bytes.Repeat([]byte{0xff}, 16))
	for range 64 {
		emit(testutil.EthIPv6UDP(ones, ones, 0xffff, 0xffff))
	}
	zero := make([]byte, 10)
	for i := range 64 {
		rec := emit(testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9200, 53))
		if !bytes.Equal(rec[16:26], zero) || !bytes.Equal(rec[32:42], zero) {
			t.Fatalf("ipv4 record %d keeps bytes of an older record: % x", i, rec)
		}
	}
}

func TestSampledOnlyKeepsNoInterfaceCounters(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 1, WakeupBatch: 1, SampledOnly: true})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	if n := p.objs.RfmIfaceArr.MaxEntries(); n != 1 {
		t.Fatalf("counter array of %d entries in sampled only mode, want 1", n)
	}
	p.mu.Lock()
	held := p.slots.held()
	p.mu.Unlock()
	if len(held) != 0 {
		t.Fatalf("slots in sampled only mode = %v, want none", held)
	}
	rd := newFlowReader(t, p)

	// the packet is sampled, its event carries what the exact counters
	// would have counted, and no counter moves
	pkt := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9300, 53)
	ns.SendRaw(t, pkt)
	deadline := time.Now().Add(time.Second)
	for {
		raw, err := rd.read(deadline)
		if err != nil {
			t.Fatalf("read flow event: %v", err)
		}
		ev, err := collector.DecodeFlowEvent(raw)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Ifindex == uint32(ns.Ifindex()) && ev.SrcPort == 9300 {
			if ev.Segs != 1 || ev.Len != uint32(len(pkt)) {
				t.Fatalf("event of %d segments and %d bytes, want 1 and %d", ev.Segs, ev.Len, len(pkt))
			}
			break
		}
	}
	counters, err := p.Counters()
	if err != nil {
		t.Fatal(err)
	}
	if len(counters) != 0 {
		t.Fatalf("counters in sampled only mode = %+v, want none", counters)
	}
}

func TestSampledOnlyLeavesThePinsAlone(t *testing.T) {
	testutil.RequireRoot(t)

	dir := pinDir(t)
	ns := testutil.NewNS(t)
	key := rfmRfmIfaceKey{Ifindex: uint32(ns.Ifindex()), Dir: 0, Proto: 4}
	pkt := testutil.EthIPv4TCP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9400, 80)

	p, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	if _, err := p.attach(ns.Ifindex(), ns.Name()); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		p.Close()
		t.Fatal(err)
	}
	ns.SendRaw(t, pkt)
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

	// sampled only shows none of the pinned counters, which would stay
	// flat while it runs, and changes none of them
	ps, err := Load(Config{SampleRate: 1, WakeupBatch: 1, PinPath: dir, SampledOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ps.attach(ns.Ifindex(), ns.Name()); err != nil {
		ps.Close()
		t.Fatal(err)
	}
	ns.SendRaw(t, pkt)
	counters, err := ps.Counters()
	if err != nil {
		ps.Close()
		t.Fatal(err)
	}
	if err := ps.Close(); err != nil {
		t.Fatal(err)
	}
	if len(counters) != 0 {
		t.Fatalf("counters in sampled only mode = %+v, want none of the pinned ones", counters)
	}

	// the next exact load carries on from the pins
	p2, err := Load(Config{SampleRate: 1 << 30, WakeupBatch: 1, PinPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	if after, _ := ifaceStats(t, p2, key); after != before {
		t.Fatalf("packets after a sampled only run = %d, want %d from the pins", after, before)
	}
}

func TestSampledOnlyKeepsTheRate(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)

	p, err := Load(Config{SampleRate: 10, WakeupBatch: 1, SampledOnly: true})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	// the skip count of each CPU puts 2000 samples in 20000 packets
	if got := loopbackSamples(t, p, 20000); got < 1800 || got > 2200 {
		t.Fatalf("samples of 20000 packets at 1 in 10 = %d, want 2000 within 200", got)
	}
	// a new rate draws again at the next packet
	if err := p.SetSampleRate(1); err != nil {
		t.Fatal(err)
	}
	if got := loopbackSamples(t, p, 5); got != 5 {
		t.Fatalf("samples of 5 packets after the rate went to 1 = %d, want 5", got)
	}
}

// stageFlush is RFM_STAGE_FLUSH_NS in bpf/rfm_tc.c, the timer of a stage
// writes it this long after the run that armed it
const stageFlush = 10 * time.Millisecond

// readDeadline is the read deadline of the collector, a staged event reaches
// the reader within the flush interval and that deadline
const readDeadline = 100 * time.Millisecond

// eventSize is the size of struct rfm_flow_event, a record of the stage
// programs holds several back to back
const eventSize = int(unsafe.Sizeof(rfmRfmStage{}.Ev[0]))

// the four stage programs, exact and sampled only in both directions
var stageModes = []struct {
	name        string
	sampledOnly bool
	egress      bool
}{
	{"exact ingress", false, false},
	{"exact egress", false, true},
	{"sampled only ingress", true, false},
	{"sampled only egress", true, true},
}

// stageOf returns the stage of cpu
func stageOf(t *testing.T, p *Probe, cpu int) rfmRfmStage {
	t.Helper()

	var vals []rfmRfmStage
	if err := p.objs.RfmCpuStage.Lookup(uint32(0), &vals); err != nil {
		t.Fatal(err)
	}
	return vals[cpu]
}

// waitStageIdle waits until the stage of cpu holds no event and no flush of
// it is pending
func waitStageIdle(t *testing.T, p *Probe, cpu int) {
	t.Helper()

	testutil.Eventually(t, time.Second, time.Millisecond, func() error {
		if st := stageOf(t, p, cpu); st.N != 0 || st.Armed != 0 {
			return fmt.Errorf("stage of cpu %d holds %d events, its flush armed at %d", cpu, st.N, st.Armed)
		}
		return nil
	})
}

// stageRuns runs prog repeat times on each frame once the stage of cpu is
// idle, and reports whether the runs ended within the flush interval of the
// first, so the timer the first armed has not written their stage
func stageRuns(t *testing.T, p *Probe, cpu int, prog *ebpf.Program, repeat uint32, frames ...[]byte) bool {
	t.Helper()

	waitStageIdle(t, p, cpu)
	start := time.Now()
	for _, frame := range frames {
		if _, err := prog.Run(&ebpf.RunOptions{Data: frame, Repeat: repeat}); err != nil {
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
	}
	return time.Since(start) < stageFlush
}

// untilWithinFlush calls attempt until one reports that its runs ended within
// the flush interval, a loaded machine stretches some of them past it
func untilWithinFlush(t *testing.T, attempt func() bool) {
	t.Helper()

	for i := 1; !attempt(); i++ {
		if i == 20 {
			t.Fatalf("the runs of %d attempts took longer than the %v flush interval", i, stageFlush)
		}
	}
}

// drainRecords waits for the flush of the stage of cpu and reads every record
// in the rings
func drainRecords(t *testing.T, p *Probe, cpu int, rd *flowReader) {
	t.Helper()

	waitStageIdle(t, p, cpu)
	for {
		if _, err := rd.read(time.Now()); err != nil {
			return
		}
	}
}

// bootTime reads CLOCK_BOOTTIME, the clock of the event timestamps
func bootTime(t *testing.T) time.Duration {
	t.Helper()

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Fatal(err)
	}
	return time.Duration(ts.Nano())
}

func TestLoadRefusesAStageAboveItsSize(t *testing.T) {
	// the stage of each CPU holds RFM_STAGE_MAX events
	p, err := Load(Config{SampleRate: 1, WakeupBatch: 1, StageEvents: maxStageEvents + 1})
	if err == nil {
		p.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "stage events") {
		t.Fatalf("load with a stage of %d events = %v, want it refused", maxStageEvents+1, err)
	}
}

func TestStageOfOneEventWritesEveryEventAtOnce(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)
	cpu := pinOneCPU(t)

	p, err := Load(Config{SampleRate: 1, WakeupBatch: 1, StageEvents: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	rd := newFlowReader(t, p)

	frame := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9500, 53)
	if _, err := p.ingress.Run(&ebpf.RunOptions{Data: frame}); err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	// the programs without a stage put the event in the ring before the run returns
	raw, err := rd.read(time.Now())
	if err != nil {
		t.Fatalf("event after the run: %v", err)
	}
	if len(raw) != eventSize {
		t.Fatalf("record of %d bytes, want one event of %d", len(raw), eventSize)
	}
	if st := stageOf(t, p, cpu); st.N != 0 || st.Armed != 0 || st.Ready != 0 {
		t.Fatalf("stage of a load of one event a record holds %d events, armed at %d, ready %d, want it untouched", st.N, st.Armed, st.Ready)
	}
}

func TestStageWritesItsEventsAsOneRecord(t *testing.T) {
	testutil.RequireRoot(t)

	for _, mode := range stageModes {
		t.Run(mode.name, func(t *testing.T) {
			testutil.NewNS(t)
			cpu := pinOneCPU(t)

			p, err := Load(Config{SampleRate: 1, WakeupBatch: 1, StageEvents: 4, SampledOnly: mode.sampledOnly})
			if err != nil {
				testutil.SkipIfUnprivileged(t, err)
				t.Fatal(err)
			}
			defer p.Close()
			prog, dir := p.ingress, uint8(0)
			if mode.egress {
				prog, dir = p.egress, 1
			}
			lo, err := netlink.LinkByName("lo")
			if err != nil {
				t.Fatal(err)
			}
			rd := newFlowReader(t, p)

			frames := make([][]byte, 4)
			for i := range frames {
				frames[i] = testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), uint16(9300+i), 53)
			}
			// four runs within the flush interval fill the stage before its timer writes it
			untilWithinFlush(t, func() bool {
				if stageRuns(t, p, cpu, prog, 1, frames...) {
					return true
				}
				drainRecords(t, p, cpu, rd)
				return false
			})

			raw, err := rd.read(time.Now().Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			evs, err := collector.DecodeFlowEvents(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(evs) != len(frames) {
				t.Fatalf("record of %d events, want the %d of a full stage", len(evs), len(frames))
			}
			for i, ev := range evs {
				if ev.Ifindex != uint32(lo.Attrs().Index) || ev.Dir != dir || ev.Proto != 17 || ev.SrcPort != uint16(9300+i) || ev.DstPort != 53 ||
					ev.Segs != 1 || ev.Len != uint32(len(frames[i])) || ev.L2Len != 14 {
					t.Fatalf("event %d = %+v, want the frame of port %d in direction %d", i, ev, 9300+i, dir)
				}
				if i > 0 && ev.Tstamp < evs[i-1].Tstamp {
					t.Fatalf("event %d staged at %v, before event %d at %v", i, ev.Tstamp, i-1, evs[i-1].Tstamp)
				}
			}
			// the stage went out full, its timer finds nothing to write
			waitStageIdle(t, p, cpu)
			if raw, err := rd.read(time.Now()); err == nil {
				t.Fatalf("another record of %d bytes, want the events in one", len(raw))
			}
		})
	}
}

func TestStageFlushesAPartialStageWithinTheInterval(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)
	cpu := pinOneCPU(t)

	p, err := Load(Config{SampleRate: 1, WakeupBatch: 1, StageEvents: 8})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	rd := newFlowReader(t, p)

	frame := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9400, 53)
	// three events within the interval leave the stage short of its eight
	var raw []byte
	var read time.Duration
	untilWithinFlush(t, func() bool {
		if !stageRuns(t, p, cpu, p.ingress, 3, frame) {
			drainRecords(t, p, cpu, rd)
			return false
		}
		if raw, err = rd.read(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("partial stage never reached the ring: %v", err)
		}
		read = bootTime(t)
		return true
	})

	evs, err := collector.DecodeFlowEvents(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 {
		t.Fatalf("flushed record of %d events, want the 3 staged", len(evs))
	}
	// the first event armed the timer, which writes the stage an interval later and not before
	age := read - evs[0].Tstamp
	t.Logf("the first event reached the reader %v after it was staged", age)
	if age < stageFlush || age > stageFlush+readDeadline {
		t.Fatalf("first event read %v after it was staged, want the %v flush interval and at most the %v read deadline after it", age, stageFlush, readDeadline)
	}
	if st := stageOf(t, p, cpu); st.N != 0 || st.Armed != 0 {
		t.Fatalf("stage after its flush holds %d events, armed at %d, want it empty with no flush pending", st.N, st.Armed)
	}
}

func TestStageDropsCountEveryEvent(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)
	cpu := pinOneCPU(t)

	frame := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9600, 53)
	untilWithinFlush(t, func() bool {
		// a ring of one page takes four records of 16 events, 904 bytes with
		// their headers, and leaves 480 bytes
		p, err := Load(Config{SampleRate: 1, WakeupBatch: 1, RingBufSize: 4096, StageEvents: 16})
		if err != nil {
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
		defer p.Close()

		for _, step := range []struct {
			runs  uint32
			drops uint64
		}{
			// four full records fill the ring, the timer's record of the 9 left needs 512 bytes
			{73, 9},
			// a full record of 16 events finds no room either
			{16, 25},
			// the timer's record of 8 events fits in 456 bytes
			{8, 25},
		} {
			if !stageRuns(t, p, cpu, p.ingress, step.runs, frame) {
				return false
			}
			waitStageIdle(t, p, cpu)
			if got := flowDrops(t, p); got != step.drops {
				t.Fatalf("drops after %d more runs = %d, want %d", step.runs, got, step.drops)
			}
		}

		rd := newFlowReader(t, p)
		var sizes []int
		for {
			raw, err := rd.read(time.Now())
			if err != nil {
				break
			}
			sizes = append(sizes, len(raw)/eventSize)
		}
		if want := []int{16, 16, 16, 16, 8}; !slices.Equal(sizes, want) {
			t.Fatalf("records of %v events, want %v", sizes, want)
		}
		return true
	})
}

func TestStageWakeupCountsTheEventsOfTheCPU(t *testing.T) {
	testutil.RequireRoot(t)

	testutil.NewNS(t)
	cpu := pinOneCPU(t)

	frame := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9700, 53)
	untilWithinFlush(t, func() bool {
		p, err := Load(Config{SampleRate: 1, WakeupBatch: 8, StageEvents: 4})
		if err != nil {
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
		defer p.Close()

		// the first record wakes the reader, and so does every record that
		// brings the events written since the last wakeup to the batch
		for i, step := range []struct{ runs, wake uint32 }{
			{4, 8}, {4, 4}, {4, 8}, {4, 4},
			// the timer writes a partial stage under the same countdown
			{3, 1}, {1, 8},
		} {
			if !stageRuns(t, p, cpu, p.ingress, step.runs, frame) {
				return false
			}
			waitStageIdle(t, p, cpu)
			if got := stageOf(t, p, cpu).Wake; got != step.wake {
				t.Fatalf("after record %d of %d events the cpu waits %d events to wake, want %d", i+1, step.runs, got, step.wake)
			}
		}

		// the stage counts down for every interface of the CPU, the draw entry keeps no countdown
		var vals []rfmRfmSlotValue
		if err := p.objs.RfmCpuDraw.Lookup(uint32(0), &vals); err != nil {
			t.Fatal(err)
		}
		if vals[cpu].Wake != 0 {
			t.Fatalf("draw entry of the cpu waits %d events to wake, want no countdown", vals[cpu].Wake)
		}
		return true
	})
}

func TestStageKeepsTheRate(t *testing.T) {
	testutil.RequireRoot(t)

	for _, sampledOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("sampled only %v", sampledOnly), func(t *testing.T) {
			testutil.NewNS(t)

			p, err := Load(Config{SampleRate: 10, WakeupBatch: 1, StageEvents: 16, SampledOnly: sampledOnly})
			if err != nil {
				testutil.SkipIfUnprivileged(t, err)
				t.Fatal(err)
			}
			defer p.Close()

			// every sampled run is an event of a record or a drop
			if got := loopbackSamples(t, p, 20000); got < 1800 || got > 2200 {
				t.Fatalf("samples of 20000 packets at 1 in 10 = %d, want 2000 within 200", got)
			}
		})
	}
}
