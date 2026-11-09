//go:build linux

package probe

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/testutil"
)

// setOnline makes Load and WatchCPUs see the CPUs online reads back until the test ends
func setOnline(t *testing.T, online func() []int) {
	t.Helper()

	saved := readOnline
	readOnline = func() ([]int, error) { return online(), nil }
	t.Cleanup(func() { readOnline = saved })
}

// possibleCPUs returns every possible CPU, skipping the test below two
func possibleCPUs(t *testing.T) []int {
	t.Helper()

	n, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Skip("needs two possible CPUs")
	}
	cpus := make([]int, n)
	for i := range cpus {
		cpus[i] = i
	}
	return cpus
}

func TestLoadGivesRingsToTheOnlineCPUsOnly(t *testing.T) {
	testutil.RequireRoot(t)
	all := possibleCPUs(t)
	setOnline(t, func() []int { return []int{1} })

	p, err := Load(Config{SampleRate: 1, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()

	if n := len(p.FlowRings()); n != 1 {
		t.Fatalf("%d rings with one CPU online, want 1", n)
	}
	// the array keeps a slot for every possible CPU, the offline ones empty
	if got := p.objs.RfmFlowRings.MaxEntries(); got != uint32(len(all)) {
		t.Fatalf("ring array of %d slots, want one per possible CPU, %d", got, len(all))
	}
	var id ebpf.MapID
	if err := p.objs.RfmFlowRings.Lookup(uint32(1), &id); err != nil {
		t.Fatalf("ring of the online CPU: %v", err)
	}
	if err := p.objs.RfmFlowRings.Lookup(uint32(0), &id); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("ring of an offline CPU = %d, %v, want none", id, err)
	}
}

func TestReadOnlineReadsSysfs(t *testing.T) {
	// a build sandbox has no sysfs
	if _, err := os.Stat(onlinePath); err != nil {
		t.Skipf("no %s: %v", onlinePath, err)
	}
	cpus, err := readOnline()
	if err != nil || len(cpus) == 0 {
		t.Fatalf("online CPUs = %v, %v, want at least one", cpus, err)
	}
}

func TestWatchCPUsGivesACPUWithoutARingItsRing(t *testing.T) {
	for _, tc := range []struct {
		name string
		// shown makes the online list show the CPU of the test once it watches
		shown bool
	}{
		{"online", true},
		// a container's view of the online list never shows some CPUs of the host
		{"dropping", false},
	} {
		t.Run(tc.name, func(t *testing.T) { watchCPUs(t, tc.shown) })
	}
}

// watchCPUs runs the programs on a CPU Load left without a ring, then has
// WatchCPUs give it one, from the online list when shown and from its drops
// otherwise
func watchCPUs(t *testing.T, shown bool) {
	testutil.RequireRoot(t)
	all := possibleCPUs(t)
	cpu := pinOneCPU(t)
	others := slices.DeleteFunc(slices.Clone(all), func(c int) bool { return c == cpu })
	online := make(chan []int, 1)
	online <- others
	setOnline(t, func() []int { cur := <-online; online <- cur; return cur })

	p, err := Load(Config{SampleRate: 1, WakeupBatch: 1})
	if err != nil {
		testutil.SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer p.Close()
	rd, err := collector.NewReader(p.FlowRings(), p.FlowDrops())
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.WatchCPUs(ctx, 10*time.Millisecond, rd.(interface{ AddRing(*ebpf.Map) error }).AddRing)
	}()
	defer func() { cancel(); <-done }()

	// the CPU without a ring and without drops is left alone
	time.Sleep(50 * time.Millisecond)
	if p.hasRing(cpu) {
		t.Fatal("a ring for a CPU neither online nor dropping")
	}

	// the test runs on the CPU without a ring, whose events count as drops
	frame := testutil.EthIPv4UDP(net.IPv4(10, 0, 9, 1), net.IPv4(10, 0, 9, 2), 9100, 53)
	before := flowDrops(t, p)
	if !shown {
		if _, err := p.ingress.Run(&ebpf.RunOptions{Data: frame}); err != nil {
			testutil.SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
		if got := flowDrops(t, p) - before; got != 1 {
			t.Fatalf("%d drops of an event on a CPU without a ring, want 1", got)
		}
	} else {
		<-online
		online <- all
	}
	testutil.Eventually(t, 2*time.Second, 10*time.Millisecond, func() error {
		if !p.hasRing(cpu) {
			return errors.New("no ring yet for the CPU")
		}
		return nil
	})

	before = flowDrops(t, p)
	if _, err := p.ingress.Run(&ebpf.RunOptions{Data: frame}); err != nil {
		t.Fatal(err)
	}
	rd.SetDeadline(time.Now().Add(time.Second))
	raw, err := rd.ReadRawEvent()
	if err != nil {
		t.Fatalf("read the event of the CPU that got its ring: %v", err)
	}
	ev, err := collector.DecodeFlowEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.SrcPort != 9100 || ev.DstPort != 53 {
		t.Fatalf("event of ports %d to %d, want 9100 to 53", ev.SrcPort, ev.DstPort)
	}
	if got := flowDrops(t, p) - before; got != 0 {
		t.Fatalf("%d drops once the CPU has its ring, want 0", got)
	}
	if st := p.WatchState(); st.RingErrors != 0 {
		t.Fatalf("%d ring errors, want 0", st.RingErrors)
	}
}
