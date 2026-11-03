//go:build linux

// progbench times the TC and XDP programs of a BPF object with
// BPF_PROG_TEST_RUN on crafted frames and prints one JSON line per program
// and frame with the kernel measured ns per run and the verifier's view of
// the program. With -attach it measures the object in situ on a real
// interface under external traffic (insitu.go), with -accuracy it measures
// the per-flow estimation error of the sampling draw (accuracy.go)
//
// the kernel times the run loop itself and pauses the clock across
// cond_resched, so the figure excludes syscall and scheduling overhead, and
// it is an integer number of ns per run
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// skbCtxSize and the offsets are struct __sk_buff from the UAPI headers
const (
	skbCtxSize     = 192
	offWireLen     = 160
	offGSOSegs     = 164
	offGSOSize     = 176
	bpfProgTestRun = 10 // BPF_PROG_TEST_RUN
)

// testRunAttr is the test member of union bpf_attr
type testRunAttr struct {
	progFD      uint32
	retval      uint32
	dataSizeIn  uint32
	dataSizeOut uint32
	dataIn      uint64
	dataOut     uint64
	repeat      uint32
	duration    uint32
	ctxSizeIn   uint32
	ctxSizeOut  uint32
	ctxIn       uint64
	ctxOut      uint64
	flags       uint32
	cpu         uint32
	batchSize   uint32
	_           uint32
}

type frame struct {
	data    []byte
	gsoSegs uint32
	gsoSize uint32
	// hdrLen is the L2 + L3 + L4 header size, used for the egress wire_len
	hdrLen uint32
}

type result struct {
	Label        string    `json:"label"`
	Prog         string    `json:"prog"`
	Frame        string    `json:"frame"`
	N            uint32    `json:"n"`
	Repeat       uint32    `json:"repeat"`
	NsRuns       []uint32  `json:"ns_runs"`
	NsMedian     uint32    `json:"ns_median"`
	NsMin        uint32    `json:"ns_min"`
	WallNs       []float64 `json:"wall_ns_runs"`
	Retval       uint32    `json:"retval"`
	VerifiedInsn uint32    `json:"verified_insns"`
	Processed    int       `json:"processed_insns"`
	XlatedBytes  int       `json:"xlated_bytes"`
	JitedBytes   uint32    `json:"jited_bytes"`
	Drops        uint64    `json:"ring_drops"`
	Kernel       string    `json:"kernel"`
	CPU          uint32    `json:"cpu"`
}

func main() {
	obj := flag.String("obj", "", "BPF object file")
	label := flag.String("label", "", "label for the output lines")
	progs := flag.String("progs", "auto", "comma separated program names, auto for every rfm entry point in the object")
	frames := flag.String("frames", "v4tcp,v6tcp,vlan4tcp,arp,v4tcp_gso", "comma separated frame names")
	n := flag.Uint("n", 100, "sample rate N written to the config map")
	repeat := flag.Uint("repeat", 2000000, "runs per trial")
	trials := flag.Int("trials", 7, "trials per program and frame, each on a fresh load")
	cpu := flag.Int("cpu", 2, "CPU to pin the calling thread to")
	ringOrder := flag.Uint("ring-order", 27, "log2 of the ring buffer size in bytes")
	attach := flag.String("attach", "", "attach to this interface under external traffic instead of test runs, -obj none measures with nothing attached")
	warmup := flag.Duration("warmup", 5*time.Second, "settle time before the window, with -attach")
	window := flag.Duration("window", 20*time.Second, "measurement window, with -attach")
	acc := flag.String("accuracy", "", "K:M runs K flows of exactly M packets each through the ingress program, cycling the flows, and reports the sampled estimates against that ground truth")
	flag.Parse()

	if *obj == "" || *label == "" {
		fmt.Fprintln(os.Stderr, "progbench: -obj and -label are required")
		os.Exit(2)
	}

	if err := pin(*cpu); err != nil {
		fail(err)
	}

	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		fail(err)
	}
	kernel := unix.ByteSliceToString(uts.Release[:])

	if *acc != "" {
		if err := accuracy(*obj, *label, *acc, uint32(*n), uint32(*ringOrder), kernel); err != nil {
			fail(err)
		}
		return
	}

	if *attach != "" {
		if err := insitu(*obj, *label, *attach, uint32(*n), uint32(*ringOrder), *warmup, *window, kernel); err != nil {
			fail(err)
		}
		return
	}

	names := strings.Split(*progs, ",")
	if *progs == "auto" {
		var err error
		if names, err = entryPoints(*obj); err != nil {
			fail(err)
		}
	}
	for _, pname := range names {
		for fname := range strings.SplitSeq(*frames, ",") {
			fr, err := buildFrame(fname)
			if err != nil {
				fail(err)
			}
			res := result{Label: *label, Prog: pname, Frame: fname, N: uint32(*n), Repeat: uint32(*repeat), Kernel: kernel, CPU: uint32(*cpu)}
			for t := 0; t < *trials; t++ {
				ns, wall, ret, drops, info, err := trial(*obj, pname, fr, uint32(*n), uint32(*repeat), uint32(*ringOrder))
				if err != nil {
					fail(fmt.Errorf("%s %s %s: %w", *label, pname, fname, err))
				}
				res.NsRuns = append(res.NsRuns, ns)
				res.WallNs = append(res.WallNs, wall)
				res.Retval = ret
				res.Drops = drops
				if t == 0 {
					res.VerifiedInsn = info.verified
					res.Processed = info.processed
					res.XlatedBytes = info.xlated
					res.JitedBytes = info.jited
				}
			}
			sorted := slices.Clone(res.NsRuns)
			slices.Sort(sorted)
			res.NsMedian = sorted[len(sorted)/2]
			res.NsMin = sorted[0]
			out, err := json.Marshal(res)
			if err != nil {
				fail(err)
			}
			fmt.Println(string(out))
		}
	}
}

type progInfo struct {
	verified  uint32
	processed int
	xlated    int
	jited     uint32
}

var processedRe = regexp.MustCompile(`processed (\d+) insns`)

// trial loads the object afresh, so every trial starts with empty counters,
// an empty ring and zeroed skip counts
func trial(obj, pname string, fr frame, n, repeat, ringOrder uint32) (uint32, float64, uint32, uint64, progInfo, error) {
	var info progInfo

	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return 0, 0, 0, 0, info, err
	}
	if _, ok := spec.Programs[pname]; !ok {
		return 0, 0, 0, 0, info, fmt.Errorf("no program %q", pname)
	}
	for name := range spec.Programs {
		if name != pname {
			delete(spec.Programs, name)
		}
	}
	if m, ok := spec.Maps["rfm_flow_events"]; ok {
		m.MaxEntries = 1 << ringOrder
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	})
	if err != nil {
		if ve, ok := errors.AsType[*ebpf.VerifierError](err); ok {
			return 0, 0, 0, 0, info, fmt.Errorf("%+v", ve)
		}
		return 0, 0, 0, 0, info, err
	}
	defer coll.Close()

	if err := writeConfig(coll.Maps["rfm_config"], n); err != nil {
		return 0, 0, 0, 0, info, err
	}
	// test_run hands the program the loopback device, ifindex 1, at slot 0
	if m, ok := coll.Maps["rfm_iface_slot"]; ok {
		if err := m.Put(uint32(1), uint32(1)); err != nil {
			return 0, 0, 0, 0, info, fmt.Errorf("slot: %w", err)
		}
	}

	prog := coll.Programs[pname]
	if mm := processedRe.FindStringSubmatch(prog.VerifierLog); mm != nil {
		info.processed, _ = strconv.Atoi(mm[1])
	}
	if pi, err := prog.Info(); err == nil {
		if v, ok := pi.VerifiedInstructions(); ok {
			info.verified = v
		}
		if x, err := pi.TranslatedSize(); err == nil {
			info.xlated = x
		}
		if j, err := pi.JitedSize(); err == nil {
			info.jited = j
		}
	}

	start := time.Now()
	ns, ret, err := testRun(prog.FD(), fr, repeat, prog.Type() != ebpf.XDP)
	wall := float64(time.Since(start).Nanoseconds()) / float64(repeat)
	if err != nil {
		return 0, 0, 0, 0, info, err
	}

	var drops uint64
	if m, ok := coll.Maps["rfm_flow_drops"]; ok {
		var per []uint64
		if err := m.Lookup(uint32(0), &per); err == nil {
			for _, v := range per {
				drops += v
			}
		}
	}
	return ns, wall, ret, drops, info, nil
}

// writeConfig fills the config value by its size: the agent's struct is
// sample_rate, flags, wakeup_batch and the variants append threshold
func writeConfig(m *ebpf.Map, n uint32) error {
	if m == nil {
		return errors.New("no rfm_config map")
	}
	val := make([]byte, m.ValueSize())
	binary.NativeEndian.PutUint32(val[0:], n)
	binary.NativeEndian.PutUint32(val[8:], 64)
	if len(val) >= 16 {
		thr := min(uint64(1<<32)/uint64(max(n, 1)), 0xffffffff)
		binary.NativeEndian.PutUint32(val[12:], uint32(thr))
	}
	return m.Put(uint32(0), val)
}

func testRun(fd int, fr frame, repeat uint32, skbCtx bool) (uint32, uint32, error) {
	var ctx []byte
	if skbCtx {
		ctx = make([]byte, skbCtxSize)
		if fr.gsoSize > 0 {
			binary.NativeEndian.PutUint32(ctx[offGSOSegs:], fr.gsoSegs)
			binary.NativeEndian.PutUint32(ctx[offGSOSize:], fr.gsoSize)
			// what qdisc_pkt_len_init() leaves for the egress hook
			wire := uint32(len(fr.data)) + (fr.gsoSegs-1)*fr.hdrLen
			binary.NativeEndian.PutUint32(ctx[offWireLen:], wire)
		}
	}
	attr := testRunAttr{
		progFD:     uint32(fd),
		dataSizeIn: uint32(len(fr.data)),
		dataIn:     uint64(uintptr(unsafe.Pointer(&fr.data[0]))),
		repeat:     repeat,
	}
	if ctx != nil {
		attr.ctxSizeIn = uint32(len(ctx))
		attr.ctxIn = uint64(uintptr(unsafe.Pointer(&ctx[0])))
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfProgTestRun, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(fr.data)
	runtime.KeepAlive(ctx)
	if errno != 0 {
		return 0, 0, fmt.Errorf("BPF_PROG_TEST_RUN: %w", errno)
	}
	return attr.duration, attr.retval, nil
}

func pin(cpu int) error {
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Zero()
	set.Set(cpu)
	return unix.SchedSetaffinity(0, &set)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "progbench:", err)
	os.Exit(1)
}

var (
	macDst = []byte{0x02, 0, 0, 0, 0, 0x02}
	macSrc = []byte{0x02, 0, 0, 0, 0, 0x01}
)

func eth(proto uint16) []byte {
	b := slices.Concat(macDst, macSrc)
	return binary.BigEndian.AppendUint16(b, proto)
}

func vlan(proto uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, 100)
	return binary.BigEndian.AppendUint16(b, proto)
}

func ipv4(payload int) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(20+payload))
	b[8] = 64
	b[9] = 6
	copy(b[12:], []byte{10, 0, 0, 1})
	copy(b[16:], []byte{10, 0, 0, 2})
	return b
}

func ipv6(payload int) []byte {
	b := make([]byte, 40)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(payload))
	b[6] = 6
	b[7] = 64
	b[8], b[23] = 0x20, 1
	b[24], b[39] = 0x20, 2
	return b
}

func tcp() []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], 40000)
	binary.BigEndian.PutUint16(b[2:], 443)
	b[12] = 5 << 4
	b[13] = 0x10
	return b
}

func pad(b []byte, to int) []byte {
	if len(b) < to {
		b = append(b, make([]byte, to-len(b))...)
	}
	return b
}

func buildFrame(name string) (frame, error) {
	switch name {
	case "v4tcp":
		return frame{data: pad(slices.Concat(eth(0x0800), ipv4(20), tcp()), 64)}, nil
	case "v6tcp":
		return frame{data: pad(slices.Concat(eth(0x86dd), ipv6(20), tcp()), 64)}, nil
	case "vlan4tcp":
		return frame{data: pad(slices.Concat(eth(0x8100), vlan(0x0800), ipv4(20), tcp()), 64)}, nil
	case "arp":
		return frame{data: pad(eth(0x0806), 64)}, nil
	case "v4tcp_gso":
		// two 1448 byte segments merged, as GRO hands them to TCX ingress
		const mss, segs = 1448, 2
		d := slices.Concat(eth(0x0800), ipv4(20+mss*segs), tcp(), make([]byte, mss*segs))
		return frame{data: d, gsoSegs: segs, gsoSize: mss, hdrLen: 54}, nil
	}
	return frame{}, fmt.Errorf("unknown frame %q", name)
}

// entryPoints lists the rfm programs an object carries, in a fixed order
func entryPoints(obj string) ([]string, error) {
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, name := range []string{"rfm_tc_ingress", "rfm_xdp", "rfm_tc_egress"} {
		if _, ok := spec.Programs[name]; ok {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s has no rfm program", obj)
	}
	return names, nil
}
