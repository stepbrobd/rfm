//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// insituResult is one window of an object attached to a real interface
// under external traffic, obj "none" measures the interface with nothing
// attached
type insituResult struct {
	Label       string  `json:"label"`
	Iface       string  `json:"iface"`
	N           uint32  `json:"n"`
	Seconds     float64 `json:"seconds"`
	RxPps       float64 `json:"rx_pps"`
	BusyCores   float64 `json:"busy_cores"`
	SoftirqCore float64 `json:"softirq_cores"`
	IngressRuns uint64  `json:"ingress_runs"`
	IngressNs   float64 `json:"ingress_ns_per_run"`
	EgressRuns  uint64  `json:"egress_runs"`
	EgressNs    float64 `json:"egress_ns_per_run"`
	EventsPs    float64 `json:"events_ps"`
	Drops       uint64  `json:"ring_drops"`
	// wire ground truth from the mlx5 port counters, the driver count, the
	// object's own exact ingress counters and the number of skbs (or frames
	// under XDP) the ingress program saw, all over the window
	WirePkts  uint64 `json:"wire_rx_packets"`
	WireBytes uint64 `json:"wire_rx_bytes"`
	DrvPkts   uint64 `json:"drv_rx_packets"`
	RfmPkts   uint64 `json:"rfm_rx_packets"`
	RfmBytes  uint64 `json:"rfm_rx_bytes"`
	XDP       bool   `json:"xdp"`
	Kernel    string `json:"kernel"`
}

func insitu(obj, label, iface string, n uint32, ringOrder uint32, warmup, window time.Duration, kernel string) error {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	res := insituResult{Label: label, Iface: iface, N: n, Kernel: kernel}

	var coll *ebpf.Collection
	var events atomic.Uint64
	if obj != "none" {
		spec, err := ebpf.LoadCollectionSpec(obj)
		if err != nil {
			return err
		}
		sizeRings(spec, ringOrder)
		coll, err = ebpf.NewCollection(spec)
		if err != nil {
			return err
		}
		defer coll.Close()
		if err := writeConfig(coll, n); err != nil {
			return err
		}
		rings, own, err := eventRings(spec, coll, splitRing(ringOrder))
		if err != nil {
			return err
		}
		if own {
			defer closeRings(rings)
		}
		if m, ok := coll.Maps["rfm_iface_slot"]; ok {
			if err := m.Put(uint32(ifc.Index), uint32(1)); err != nil {
				return fmt.Errorf("slot: %w", err)
			}
		}

		stats, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
		if err != nil {
			return fmt.Errorf("enable stats: %w", err)
		}
		defer stats.Close()

		// the agent anchors ingress at the head and egress at the tail
		var in link.Link
		if xp, ok := coll.Programs["rfm_xdp"]; ok {
			res.XDP = true
			in, err = link.AttachXDP(link.XDPOptions{Program: xp, Interface: ifc.Index, Flags: link.XDPDriverMode})
		} else {
			in, err = link.AttachTCX(link.TCXOptions{Interface: ifc.Index, Program: coll.Programs["rfm_tc_ingress"], Attach: ebpf.AttachTCXIngress, Anchor: link.Head()})
		}
		if err != nil {
			return fmt.Errorf("attach ingress: %w", err)
		}
		defer in.Close()
		out, err := link.AttachTCX(link.TCXOptions{Interface: ifc.Index, Program: coll.Programs["rfm_tc_egress"], Attach: ebpf.AttachTCXEgress, Anchor: link.Tail()})
		if err != nil {
			return fmt.Errorf("attach egress: %w", err)
		}
		defer out.Close()

		// a reader per ring, each drains its ring until it is closed
		for _, ring := range rings {
			rd, err := ringbuf.NewReader(ring)
			if err != nil {
				return err
			}
			defer rd.Close()
			go func() {
				var rec ringbuf.Record
				for {
					rd.SetDeadline(time.Now().Add(50 * time.Millisecond))
					if err := rd.ReadInto(&rec); err != nil {
						if errors.Is(err, ringbuf.ErrClosed) {
							return
						}
						continue
					}
					events.Add(1)
				}
			}()
		}
	}

	time.Sleep(warmup)

	inName := "rfm_tc_ingress"
	if res.XDP {
		inName = "rfm_xdp"
	}
	i0, e0 := progStats(coll, inName), progStats(coll, "rfm_tc_egress")
	w0, err := phyCounters(iface)
	if err != nil {
		return err
	}
	p0, b0 := ingressCounters(coll, ifc.Index)
	c0, err := cpuJiffies()
	if err != nil {
		return err
	}
	r0, err := rxPackets(iface)
	if err != nil {
		return err
	}
	ev0 := events.Load()
	d0 := drops(coll)
	t0 := time.Now()

	time.Sleep(window)

	i1, e1 := progStats(coll, inName), progStats(coll, "rfm_tc_egress")
	w1, err := phyCounters(iface)
	if err != nil {
		return err
	}
	p1, b1 := ingressCounters(coll, ifc.Index)
	c1, err := cpuJiffies()
	if err != nil {
		return err
	}
	r1, err := rxPackets(iface)
	if err != nil {
		return err
	}
	secs := time.Since(t0).Seconds()

	const hz = 100 // USER_HZ
	res.Seconds = secs
	res.RxPps = float64(r1-r0) / secs
	res.BusyCores = float64(c1.busy-c0.busy) / hz / secs
	res.SoftirqCore = float64(c1.softirq-c0.softirq) / hz / secs
	res.IngressRuns = i1.RunCount - i0.RunCount
	if res.IngressRuns > 0 {
		res.IngressNs = float64(i1.Runtime-i0.Runtime) / float64(res.IngressRuns)
	}
	res.EgressRuns = e1.RunCount - e0.RunCount
	if res.EgressRuns > 0 {
		res.EgressNs = float64(e1.Runtime-e0.Runtime) / float64(res.EgressRuns)
	}
	res.EventsPs = float64(events.Load()-ev0) / secs
	res.Drops = drops(coll) - d0
	res.WirePkts = w1.pkts - w0.pkts
	res.WireBytes = w1.bytes - w0.bytes
	res.DrvPkts = r1 - r0
	res.RfmPkts = p1 - p0
	res.RfmBytes = b1 - b0

	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func progStats(coll *ebpf.Collection, name string) ebpf.ProgramStats {
	if coll == nil {
		return ebpf.ProgramStats{}
	}
	s, err := coll.Programs[name].Stats()
	if err != nil {
		return ebpf.ProgramStats{}
	}
	return *s
}

func drops(coll *ebpf.Collection) uint64 {
	if coll == nil {
		return 0
	}
	m, ok := coll.Maps["rfm_flow_drops"]
	if !ok {
		return 0
	}
	var per []uint64
	if err := m.Lookup(uint32(0), &per); err != nil {
		return 0
	}
	var sum uint64
	for _, v := range per {
		sum += v
	}
	return sum
}

type jiffies struct{ busy, softirq uint64 }

// cpuJiffies sums the aggregate cpu line of /proc/stat, busy is everything
// but idle and iowait
func cpuJiffies() (jiffies, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return jiffies{}, err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if len(f) < 8 || f[0] != "cpu" {
		return jiffies{}, fmt.Errorf("unexpected /proc/stat line %q", line)
	}
	var v []uint64
	for _, s := range f[1:] {
		x, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return jiffies{}, err
		}
		v = append(v, x)
	}
	var total uint64
	for _, x := range v {
		total += x
	}
	// user nice system idle iowait irq softirq steal guest guest_nice, guest
	// time is already inside user
	if len(v) >= 10 {
		total -= v[8] + v[9]
	}
	return jiffies{busy: total - v[3] - v[4], softirq: v[6]}, nil
}

func rxPackets(iface string) (uint64, error) {
	b, err := os.ReadFile("/sys/class/net/" + iface + "/statistics/rx_packets")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

type phy struct{ pkts, bytes uint64 }

// phyCounters reads the port counters of an mlx5 NIC, which count frames on
// the wire before the driver and GRO, FCS included in the bytes
func phyCounters(iface string) (phy, error) {
	out, err := exec.Command("ethtool", "-S", iface).Output()
	if err != nil {
		return phy{}, fmt.Errorf("ethtool -S %s: %w", iface, err)
	}
	var w phy
	for line := range strings.SplitSeq(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		x, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "rx_packets_phy":
			w.pkts = x
		case "rx_bytes_phy":
			w.bytes = x
		}
	}
	return w, nil
}

type hashKey struct {
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	_       uint16
}

type hashValue struct{ Packets, Bytes uint64 }

// ingressCounters sums the object's exact ingress counters for one interface
// over every family and CPU, the array slot 0 the harness assigns and the
// hash fallback
func ingressCounters(coll *ebpf.Collection, ifindex int) (uint64, uint64) {
	if coll == nil {
		return 0, 0
	}
	var pkts, bytes uint64
	if m, ok := coll.Maps["rfm_iface_arr"]; ok {
		// every build leads its value with the two counters, the fields
		// after them differ, so each CPU's value is read up to its stride
		stride := (int(m.ValueSize()) + 7) &^ 7
		for idx := range uint32(3) {
			buf, err := m.LookupBytes(idx)
			if err != nil {
				continue
			}
			for off := 0; off+16 <= len(buf); off += stride {
				pkts += binary.NativeEndian.Uint64(buf[off:])
				bytes += binary.NativeEndian.Uint64(buf[off+8:])
			}
		}
	}
	if m, ok := coll.Maps["rfm_iface_stats"]; ok {
		var k hashKey
		var per []hashValue
		it := m.Iterate()
		for it.Next(&k, &per) {
			if int(k.Ifindex) != ifindex || k.Dir != 0 {
				continue
			}
			for _, v := range per {
				pkts += v.Packets
				bytes += v.Bytes
			}
		}
	}
	return pkts, bytes
}
