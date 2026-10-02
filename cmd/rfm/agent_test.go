package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"structs"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
	"ysun.co/rfm/export"
	"ysun.co/rfm/probe"
	"ysun.co/rfm/testutil"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rfm.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeProbe stands in for the BPF programs, it keeps the attached
// interfaces and the sample rate in memory and its reader hands out the
// events a test sends on events
type fakeProbe struct {
	mu       sync.Mutex
	cfg      probe.Config
	attached map[int]bool
	rate     uint32
	watching bool
	closed   bool
	events   chan []byte
}

func newFakeProbe() *fakeProbe {
	return &fakeProbe{attached: map[int]bool{}, events: make(chan []byte, 16)}
}

func (f *fakeProbe) load(cfg probe.Config) (agentProbe, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg, f.rate = cfg, cfg.SampleRate
	return f, nil
}

func (f *fakeProbe) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeProbe) Attach(ifindex int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attached[ifindex] = true
	return nil
}

func (f *fakeProbe) Attached() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []int
	for ifindex := range f.attached {
		out = append(out, ifindex)
	}
	return out
}

func (f *fakeProbe) SetSampleRate(n uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rate = n
	return nil
}

func (f *fakeProbe) sampleRate() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rate
}

func (f *fakeProbe) Watch(ctx context.Context, match func(string) bool, notify func(probe.LinkEvent)) error {
	f.mu.Lock()
	f.watching = true
	f.mu.Unlock()
	<-ctx.Done()
	f.mu.Lock()
	f.watching = false
	f.mu.Unlock()
	return ctx.Err()
}

func (f *fakeProbe) WatchState() probe.WatchState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return probe.WatchState{Running: f.watching, Synced: f.watching}
}

func (f *fakeProbe) Stats() export.IfaceStatsSource { return fakeStats{f} }

func (f *fakeProbe) Events() (collector.Reader, error) {
	return &fakeReader{events: f.events}, nil
}

// fakeStats reports one received ipv4 packet on every attached interface
type fakeStats struct{ f *fakeProbe }

func (s fakeStats) IfaceStats() ([]export.IfaceStatsEntry, error) {
	var out []export.IfaceStatsEntry
	for _, ifindex := range s.f.Attached() {
		out = append(out, export.IfaceStatsEntry{Ifindex: uint32(ifindex), Proto: 4, Packets: 1, Bytes: 100})
	}
	return out, nil
}

func (s fakeStats) SampleRate() (uint32, error) { return s.f.sampleRate(), nil }

// fakeReader hands out the events sent on events and otherwise waits for its
// deadline the way the ring buffer reader does
type fakeReader struct {
	mu       sync.Mutex
	deadline time.Time
	events   <-chan []byte
}

func (r *fakeReader) SetDeadline(t time.Time) {
	r.mu.Lock()
	r.deadline = t
	r.mu.Unlock()
}

func (r *fakeReader) ReadRawEvent() ([]byte, error) {
	r.mu.Lock()
	wait := time.Until(r.deadline)
	r.mu.Unlock()
	timer := time.NewTimer(max(wait, 0))
	defer timer.Stop()
	select {
	case raw := <-r.events:
		return raw, nil
	case <-timer.C:
		return nil, os.ErrDeadlineExceeded
	}
}

func (r *fakeReader) DroppedEvents() (uint64, error) { return 0, nil }

func (r *fakeReader) Close() error { return nil }

// wireFlowEvent is struct rfm_flow_event as the BPF program writes it
type wireFlowEvent struct {
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

// rawTCPEvent is one sampled ingress TCP packet of size bytes, its zero
// timestamp reads as now
func rawTCPEvent(t *testing.T, ifindex int, src, dst string, srcPort, dstPort uint16, size uint32) []byte {
	t.Helper()
	ev := wireFlowEvent{
		Ifindex: uint32(ifindex), Proto: 6, Segs: 1,
		SrcAddr: netip.MustParseAddr(src).As16(), DstAddr: netip.MustParseAddr(dst).As16(),
		SrcPort: srcPort, DstPort: dstPort, Len: size, L2Len: 14,
	}
	raw, err := binary.Append(nil, binary.NativeEndian, ev)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// testListen opens the metrics listener on a free loopback port whatever
// the configuration asks for, and reports where
func testListen(addr chan<- string) func(network, address string) (net.Listener, error) {
	return func(network, _ string) (net.Listener, error) {
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err == nil {
			addr <- ln.Addr().String()
		}
		return ln, err
	}
}

// noProbe is for starts that must fail before the probe is loaded
func noProbe(t *testing.T) agentDeps {
	return agentDeps{
		loadProbe: func(probe.Config) (agentProbe, error) {
			t.Error("probe loaded")
			return nil, errors.New("no probe in this test")
		},
		listen: func(string, string) (net.Listener, error) {
			t.Error("metrics listener opened")
			return nil, errors.New("no listener in this test")
		},
	}
}

// agentRun is an agent a test started
type agentRun struct {
	cancel  context.CancelFunc
	done    chan error
	metrics string
}

// startAgent runs the agent on cfgPath until the test stops it, and waits
// for its metrics listener
func startAgent(t *testing.T, cfgPath string, deps agentDeps) *agentRun {
	t.Helper()

	addr := make(chan string, 1)
	if deps.listen == nil {
		deps.listen = testListen(addr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &agentRun{cancel: cancel, done: make(chan error, 1)}
	go func() { run.done <- runAgent(ctx, cfgPath, deps) }()
	t.Cleanup(func() { run.stop(t) })

	select {
	case a := <-addr:
		run.metrics = "http://" + a + "/metrics"
	case err := <-run.done:
		run.done <- err
		t.Fatalf("agent stopped while starting: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not open its metrics listener")
	}
	return run
}

// stop cancels the agent and returns what it returned
func (r *agentRun) stop(t *testing.T) error {
	t.Helper()

	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not stop")
		return nil
	}
}

// get returns the body of url
func get(t *testing.T, url string) string {
	t.Helper()

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("get %s = %d, %v", url, resp.StatusCode, err)
	}
	return string(body)
}

// waitCLI runs the command line against the agent's socket until it
// succeeds and returns what it printed
func waitCLI(t *testing.T, sock string, args ...string) string {
	t.Helper()

	var out string
	testutil.Eventually(t, 5*time.Second, 20*time.Millisecond, func() error {
		var err error
		out, err = runCLI(t, sock, args...)
		return err
	})
	return out
}

// mustInterface returns the named host interface
func mustInterface(t *testing.T, name string) *net.Interface {
	t.Helper()

	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return iface
}

func TestRunAgentWithConfig(t *testing.T) {
	lo := testutil.LoopbackName(t)
	loIndex := mustInterface(t, lo).Index
	sock := filepath.Join(t.TempDir(), "rfm.sock")
	cfgPath := writeTestConfig(t, fmt.Sprintf(`
[agent]
interfaces = [%q]

[agent.bpf]
sample_rate = 10

[agent.control]
socket = %q
`, lo, sock))

	f := newFakeProbe()
	run := startAgent(t, cfgPath, agentDeps{loadProbe: f.load})

	// the real control handler answers from the running agent
	status := waitCLI(t, sock, "status")
	for _, want := range []string{"interfaces  " + lo, "1 in 10", "0 active of 65536"} {
		if !strings.Contains(status, want) {
			t.Fatalf("status output missing %q:\n%s", want, status)
		}
	}
	if got := f.Attached(); len(got) != 1 || got[0] != loIndex || f.cfg.SampleRate != 10 {
		t.Fatalf("probe attached %v with %+v, want %s sampling 1 in 10", got, f.cfg, lo)
	}

	// a sampled event goes through the reader and the collector into the
	// flow table the command line shows
	f.events <- rawTCPEvent(t, loIndex, "::ffff:192.0.2.1", "::ffff:198.51.100.7", 40000, 443, 1500)
	testutil.Eventually(t, 5*time.Second, 20*time.Millisecond, func() error {
		if out, err := runCLI(t, sock, "flows", "count"); err != nil || strings.TrimSpace(out) != "1" {
			return fmt.Errorf("flows count = %q, %v", out, err)
		}
		return nil
	})
	top, err := runCLI(t, sock, "flows", "top")
	if err != nil || !strings.Contains(top, "192.0.2.1:40000") || !strings.Contains(top, "ingress") || !strings.Contains(top, "15000") {
		t.Fatalf("flows top = %q, %v, want the event scaled by the rate", top, err)
	}
	if fields := strings.Fields(strings.Split(top, "\n")[1]); fields[0] != lo {
		t.Fatalf("flows top = %q, want the flow on %s", top, lo)
	}

	metrics := get(t, run.metrics)
	for _, want := range []string{
		fmt.Sprintf(`rfm_interface_rx_packets_total{family="ipv4",ifname=%q} 1`, lo),
		"rfm_bpf_sample_rate 10",
		"rfm_collector_active_flows 1",
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("metrics missing %q:\n%s", want, metrics)
		}
	}

	// a sample rate change reaches the probe through the collector
	if out, err := runCLI(t, sock, "set", "sample-rate", "40"); err != nil || !strings.Contains(out, "sampling 1 in 40") || f.sampleRate() != 40 {
		t.Fatalf("set sample-rate 40 = %q, %v, probe rate %d", out, err, f.sampleRate())
	}
	if _, err := runCLI(t, sock, "set", "sample-rate", "5000"); err == nil || !strings.Contains(err.Error(), "above max_sample_rate 1000") {
		t.Fatalf("set sample-rate 5000 = %v, want it refused above max_sample_rate", err)
	}
	if out, err := runCLI(t, sock, "config", "show"); err != nil || !strings.Contains(out, sock) {
		t.Fatalf("config show = %q, %v, want the loaded file", out, err)
	}
	if _, err := runCLI(t, sock, "rib", "summary"); err == nil || !strings.Contains(err.Error(), "rib not configured") {
		t.Fatalf("rib summary without a rib = %v", err)
	}
	if _, err := runCLI(t, sock, "reload", "mmdb"); err == nil || !strings.Contains(err.Error(), "mmdb not configured") {
		t.Fatalf("reload mmdb without mmdb = %v", err)
	}

	// a stop is clean and leaves neither the probe nor the socket behind
	if err := run.stop(t); err != nil {
		t.Fatalf("agent stopped with %v, want nil", err)
	}
	if !f.closed {
		t.Fatal("probe not closed")
	}
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("control socket left behind: %v", err)
	}
}

func TestRunAgentOnTheKernelProbe(t *testing.T) {
	testutil.RequireRoot(t)

	lo := testutil.LoopbackName(t)
	sock := filepath.Join(t.TempDir(), "rfm.sock")
	cfgPath := writeTestConfig(t, fmt.Sprintf(`
[agent]
interfaces = [%q]

[agent.control]
socket = %q
`, lo, sock))

	run := startAgent(t, cfgPath, agentDeps{loadProbe: loadProbe})
	status := waitCLI(t, sock, "status")
	if !strings.Contains(status, "interfaces  "+lo) {
		t.Fatalf("status output missing %s:\n%s", lo, status)
	}
	// the scrapes run over the loopback, a later one counts an earlier one
	want := fmt.Sprintf(`rfm_interface_rx_packets_total{family="ipv4",ifname=%q}`, lo)
	testutil.Eventually(t, 5*time.Second, 50*time.Millisecond, func() error {
		if !strings.Contains(get(t, run.metrics), want) {
			return fmt.Errorf("metrics missing %s", want)
		}
		return nil
	})
	if err := run.stop(t); err != nil {
		t.Fatalf("agent stopped with %v, want nil", err)
	}
}

func TestRunAgentBadInterface(t *testing.T) {
	cfgPath := writeTestConfig(t, `
[agent]
interfaces = ["doesnotexist999"]
`)
	err := runAgent(context.Background(), cfgPath, noProbe(t))
	if err == nil {
		t.Fatal("should fail on bad interface")
	}
	if !strings.Contains(err.Error(), "doesnotexist999") {
		t.Errorf("error should mention interface name, got: %v", err)
	}
}

func TestRunAgentBadMMDBPath(t *testing.T) {
	lo := testutil.LoopbackName(t)
	cfgPath := writeTestConfig(t, fmt.Sprintf(`
[agent]
interfaces = [%q]

[agent.enrich.mmdb]
asn_db = "/does/not/exist.mmdb"
`, lo))
	err := runAgent(context.Background(), cfgPath, noProbe(t))
	if err == nil {
		t.Fatal("should fail on bad MMDB path")
	}
	if !strings.Contains(err.Error(), "/does/not/exist.mmdb") {
		t.Errorf("error should mention MMDB path, got: %v", err)
	}
}

// blockingCollector holds every gather in Collect until release is closed
type blockingCollector struct {
	entered chan struct{}
	release chan struct{}
}

var descBlocking = prometheus.NewDesc("rfm_test_blocking", "A series whose gather waits for the test.", nil, nil)

func newBlockingRegistry(t *testing.T) (*prometheus.Registry, *blockingCollector) {
	t.Helper()
	b := &blockingCollector{entered: make(chan struct{}, 16), release: make(chan struct{})}
	reg := prometheus.NewRegistry()
	reg.MustRegister(b)
	return reg, b
}

func (b *blockingCollector) Describe(ch chan<- *prometheus.Desc) { ch <- descBlocking }

func (b *blockingCollector) Collect(ch chan<- prometheus.Metric) {
	b.entered <- struct{}{}
	<-b.release
	ch <- prometheus.MustNewConstMetric(descBlocking, prometheus.GaugeValue, 1)
}

// scrape gets url and returns the status code
func scrape(client *http.Client, url string) (int, error) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, err
}

func TestMetricsServerBoundsConcurrentGathers(t *testing.T) {
	reg, b := newBlockingRegistry(t)
	ts := httptest.NewServer(newMetricsServer(reg, time.Minute).Handler)
	defer ts.Close()
	released := false
	release := func() {
		if !released {
			close(b.release)
			released = true
		}
	}
	defer release()
	client := &http.Client{Timeout: 5 * time.Second}

	codes := make(chan int, metricsInFlight)
	for range metricsInFlight {
		go func() {
			code, err := scrape(client, ts.URL+"/metrics")
			if err != nil {
				t.Error(err)
			}
			codes <- code
		}()
	}
	for range metricsInFlight {
		select {
		case <-b.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("scrapes did not reach the gather")
		}
	}

	// every slot holds a gather, one more scrape is refused at once instead
	// of gathering and holding another copy of every series
	if code, err := scrape(&http.Client{Timeout: time.Second}, ts.URL+"/metrics"); err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("scrape beyond %d gathers = %d, %v, want 503", metricsInFlight, code, err)
	}
	release()
	for range metricsInFlight {
		if code := <-codes; code != http.StatusOK {
			t.Fatalf("held scrape = %d, want 200", code)
		}
	}
}

func TestMetricsServerTimesOutAGather(t *testing.T) {
	reg, b := newBlockingRegistry(t)
	ts := httptest.NewServer(newMetricsServer(reg, 50*time.Millisecond).Handler)
	defer ts.Close()
	defer close(b.release)

	code, err := scrape(&http.Client{Timeout: 5 * time.Second}, ts.URL+"/metrics")
	if err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("scrape of a gather past the timeout = %d, %v, want 503", code, err)
	}
}

func TestMetricsServerTimeouts(t *testing.T) {
	srv := newMetricsServer(prometheus.NewRegistry(), metricsTimeout)
	if srv.ReadHeaderTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("read header timeout %v, idle timeout %v, want both set", srv.ReadHeaderTimeout, srv.IdleTimeout)
	}
	// a client that reads slowly is cut off, after a gather that took the
	// whole timeout still had time to be sent
	if srv.WriteTimeout <= metricsTimeout {
		t.Fatalf("write timeout %v, want it above the gather timeout %v", srv.WriteTimeout, metricsTimeout)
	}
}

func TestProbeConfigKeepsTheMapSizeAcrossStarts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Agent.Interfaces = []string{".*"}
	cfg.Agent.BPF = config.BPFConfig{SampleRate: 10, RingBufSize: 1 << 20, WakeupBatch: 32, PinPath: "/sys/fs/bpf/rfm"}

	// iface_stats_size 0 keeps the size the object declares, the links up at
	// one start or another must not change it, a pinned map of another size
	// fails the start
	want := probe.Config{SampleRate: 10, RingBufSize: 1 << 20, WakeupBatch: 32, PinPath: "/sys/fs/bpf/rfm"}
	if got := probeConfig(cfg); got != want {
		t.Fatalf("probe config = %+v, want %+v", got, want)
	}

	cfg.Agent.BPF.IfaceStatsSize = 8192
	if got := probeConfig(cfg).IfaceStatsSize; got != 8192 {
		t.Fatalf("iface stats size = %d, want the configured 8192", got)
	}
}

func TestRunAgentBadConfig(t *testing.T) {
	cfgPath := writeTestConfig(t, `
[agent]
interfaces = []
`)
	err := runAgent(context.Background(), cfgPath, noProbe(t))
	if err == nil {
		t.Fatal("should fail on empty interfaces")
	}
}

// freePort returns a loopback tcp port nothing listens on
func freePort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestRunAgentExportsBMPErrors(t *testing.T) {
	lo := testutil.LoopbackName(t)
	port := freePort(t)
	cfgPath := writeTestConfig(t, fmt.Sprintf(`
[agent]
interfaces = [%q]

[agent.enrich.rib.bmp]
host = "127.0.0.1"
port = %d
`, lo, port))

	addr := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- runAgent(ctx, cfgPath, agentDeps{loadProbe: newFakeProbe().load, listen: testListen(addr)})
	}()
	var url string
	select {
	case a := <-addr:
		url = "http://" + a + "/metrics"
	case err := <-done:
		t.Fatalf("agent stopped before it served metrics: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not open its metrics listener")
	}

	// the listener serves 16 sessions at once and closes the next one, a
	// session it refuses is a bmp error like a message that does not parse
	for range 17 {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
	}
	want := `rfm_errors_total{subsystem="bmp"} 1`
	testutil.Eventually(t, 5*time.Second, 20*time.Millisecond, func() error {
		if !strings.Contains(get(t, url), want) {
			return fmt.Errorf("metrics missing %s", want)
		}
		return nil
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("agent stopped with %v, want nil", err)
	}
}
