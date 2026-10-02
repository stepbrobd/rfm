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

	p, err := Load(Config{PinPath: dir})
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
	p2, err := Load(Config{PinPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	after, _ := ifaceStats(t, p2, key)
	if after != before {
		t.Fatalf("packets after reload = %d, want %d from the pinned map", after, before)
	}

	// a different map shape replaces the stale pin instead of failing
	p2.Close()
	p3, err := Load(Config{PinPath: dir, IfaceStatsSize: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer p3.Close()
	if got := p3.IfaceStats().MaxEntries(); got != 128 {
		t.Fatalf("max entries = %d, want 128", got)
	}
}

func TestWatchFollowsInterfaces(t *testing.T) {
	testutil.RequireRoot(t)

	ns := testutil.NewNS(t)

	p, err := Load(Config{})
	if err != nil {
		skipIfUnsupported(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events := make(chan LinkEvent, 16)
	watchErr := make(chan error, 1)
	// the watcher needs a thread inside the test namespace of its own,
	// the test goroutine keeps the one NewNS locked
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := netns.Set(ns.Handle()); err != nil {
			watchErr <- err
			return
		}
		watchErr <- p.Watch(ctx, func(name string) bool { return strings.HasPrefix(name, "rfmw") }, func(ev LinkEvent) {
			events <- ev
		})
	}()

	next := func() LinkEvent {
		select {
		case ev := <-events:
			return ev
		case err := <-watchErr:
			t.Fatalf("watch stopped: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for a link event")
		}
		return LinkEvent{}
	}

	// give the subscription a moment to be in place before the first link
	time.Sleep(50 * time.Millisecond)

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "rfmw0"}, PeerName: "rfmw1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}

	attached := map[string]bool{}
	for range 2 {
		ev := next()
		if !ev.Attached {
			t.Fatalf("unexpected detach event %+v", ev)
		}
		attached[ev.Name] = true
	}
	if !attached["rfmw0"] || !attached["rfmw1"] {
		t.Fatalf("attached = %v, want rfmw0 and rfmw1", attached)
	}
	if got := len(p.Attached()); got != 2 {
		t.Fatalf("attached count = %d, want 2", got)
	}

	// an interface outside the pattern is ignored
	other := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "other0"}, PeerName: "other1"}
	if err := netlink.LinkAdd(other); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(other)

	if err := netlink.LinkDel(veth); err != nil {
		t.Fatal(err)
	}
	detached := map[string]bool{}
	for range 2 {
		ev := next()
		if ev.Attached {
			t.Fatalf("unexpected attach event %+v", ev)
		}
		detached[ev.Name] = true
	}
	if !detached["rfmw0"] || !detached["rfmw1"] {
		t.Fatalf("detached = %v, want rfmw0 and rfmw1", detached)
	}
	if got := len(p.Attached()); got != 0 {
		t.Fatalf("attached count after delete = %d, want 0", got)
	}

	cancel()
	if err := <-watchErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("watch returned %v, want context.Canceled", err)
	}
}
