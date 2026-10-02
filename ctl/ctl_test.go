package ctl

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeHandler struct {
	rate     uint32
	reloaded int
	rib      bool
}

func (f *fakeHandler) Status() Status {
	return Status{
		Version:    "test",
		Uptime:     3 * time.Second,
		Interfaces: []Interface{{Name: "eth0", Ifindex: 2}},
		Sampling:   Sampling{Rate: f.rate, Base: 10, Max: 1000, Adaptive: true},
		Flows:      Flows{Active: 5, Max: 65536},
	}
}

func (f *fakeHandler) FlowsTop(n int, by string) []FlowRow {
	rows := []FlowRow{
		{Interface: "eth0", Direction: "ingress", Proto: 6, Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), SrcPort: 1, DstPort: 80, Bytes: 300, Packets: 3},
		{Interface: "eth0", Direction: "egress", Proto: 17, Src: netip.MustParseAddr("10.0.0.2"), Dst: netip.MustParseAddr("10.0.0.1"), SrcPort: 53, DstPort: 2, Bytes: 100, Packets: 5},
	}
	if by == "packets" {
		rows[0], rows[1] = rows[1], rows[0]
	}
	if n < len(rows) {
		rows = rows[:n]
	}
	return rows
}

func (f *fakeHandler) FlowsCount() uint64 { return 2 }

func (f *fakeHandler) RIBLookup(addr netip.Addr) (Route, bool, error) {
	if !f.rib {
		return Route{}, false, errors.New("rib not configured")
	}
	if addr == netip.MustParseAddr("203.0.113.9") {
		return Route{Prefix: netip.MustParsePrefix("203.0.113.0/24"), OriginASN: 64496, ASPath: []uint32{64501, 64496}}, true, nil
	}
	return Route{}, false, nil
}

func (f *fakeHandler) RIBSummary() (RIB, error) {
	if !f.rib {
		return RIB{}, errors.New("rib not configured")
	}
	return RIB{PrefixesV4: 1, Routes: 1, Peers: 1}, nil
}

func (f *fakeHandler) SetSampleRate(rate uint32) error {
	if rate > 1000 {
		return errors.New("rate above max")
	}
	f.rate = rate
	return nil
}

func (f *fakeHandler) ConfigShow() string { return "[agent]\ninterfaces = [\"eth0\"]\n" }

func (f *fakeHandler) ReloadMMDB() error {
	f.reloaded++
	return nil
}

func startServer(t *testing.T, h Handler) *Client {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "rfm.sock")
	srv, err := Listen(sock, h)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, srv)
	return &Client{Socket: sock}
}

// serve runs srv until stop is called or the test ends
func serve(t *testing.T, srv *Server) (stop func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	stop = sync.OnceFunc(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Serve returned %v", err)
		}
	})
	t.Cleanup(stop)
	return stop
}

func TestRoundTrip(t *testing.T) {
	h := &fakeHandler{rate: 10, rib: true}
	c := startServer(t, h)

	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != "test" || st.Sampling.Rate != 10 || len(st.Interfaces) != 1 || st.Interfaces[0].Name != "eth0" {
		t.Fatalf("status = %+v", st)
	}

	rows, err := c.FlowsTop(1, "packets")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Packets != 5 {
		t.Fatalf("top by packets = %+v, want the 5 packet flow", rows)
	}

	n, err := c.FlowsCount()
	if err != nil || n != 2 {
		t.Fatalf("count = %d err=%v, want 2", n, err)
	}

	route, err := c.RIBLookup(netip.MustParseAddr("203.0.113.9"))
	if err != nil {
		t.Fatal(err)
	}
	if route.OriginASN != 64496 || route.Prefix != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("route = %+v", route)
	}
	if _, err := c.RIBLookup(netip.MustParseAddr("192.0.2.1")); err == nil || !strings.Contains(err.Error(), "no route") {
		t.Fatalf("missing route error = %v", err)
	}

	sum, err := c.RIBSummary()
	if err != nil || sum.Routes != 1 {
		t.Fatalf("summary = %+v err=%v", sum, err)
	}

	if err := c.SetSampleRate(50); err != nil {
		t.Fatal(err)
	}
	if h.rate != 50 {
		t.Fatalf("handler rate = %d, want 50", h.rate)
	}
	if err := c.SetSampleRate(5000); err == nil || !strings.Contains(err.Error(), "above max") {
		t.Fatalf("set rate error = %v, want the handler's error", err)
	}

	cfg, err := c.ConfigShow()
	if err != nil || !strings.Contains(cfg, "eth0") {
		t.Fatalf("config = %q err=%v", cfg, err)
	}

	if err := c.ReloadMMDB(); err != nil || h.reloaded != 1 {
		t.Fatalf("reload err=%v count=%d", err, h.reloaded)
	}
}

func TestBadRequests(t *testing.T) {
	c := startServer(t, &fakeHandler{})

	if _, err := c.Raw("nonsense", nil); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown command error = %v", err)
	}
	if _, err := c.Raw(CmdFlowsTop, map[string]string{"n": "0"}); err == nil {
		t.Fatal("n=0 must be rejected")
	}
	if _, err := c.Raw(CmdFlowsTop, map[string]string{"by": "colour"}); err == nil {
		t.Fatal("by=colour must be rejected")
	}
	if _, err := c.Raw(CmdRIBLookup, map[string]string{"addr": "not-an-ip"}); err == nil {
		t.Fatal("bad address must be rejected")
	}
	if _, err := c.RIBSummary(); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("rib summary without rib = %v", err)
	}
	if err := c.SetSampleRate(0); err == nil {
		t.Fatal("rate 0 must be rejected")
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "rfm.sock")
	// an agent that died leaves its socket file behind
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()

	srv, err := Listen(sock, &fakeHandler{rate: 10})
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	serve(t, srv)
	if _, err := (&Client{Socket: sock}).Status(); err != nil {
		t.Fatalf("status over the replaced socket: %v", err)
	}
}

func TestListenRefusesLiveSocket(t *testing.T) {
	c := startServer(t, &fakeHandler{rate: 10})

	if srv, err := Listen(c.Socket, &fakeHandler{rate: 20}); err == nil {
		srv.listener.Close()
		t.Fatal("Listen took over the socket of a running agent")
	} else if !strings.Contains(err.Error(), "in use") {
		t.Fatalf("Listen error = %v, want the socket reported in use", err)
	}
	st, err := c.Status()
	if err != nil || st.Sampling.Rate != 10 {
		t.Fatalf("status = %+v err=%v, want the running agent", st, err)
	}
}

func TestListenKeepsNonSocketFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rfm.sock")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if srv, err := Listen(path, &fakeHandler{}); err == nil {
		srv.listener.Close()
		t.Fatal("Listen replaced a regular file")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
		t.Fatalf("file after Listen = %q err=%v, want it untouched", data, err)
	}
}

func TestServeRemovesItsSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "rfm.sock")
	srv, err := Listen(sock, &fakeHandler{})
	if err != nil {
		t.Fatal(err)
	}

	stop := serve(t, srv)
	stop()
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket after Serve stopped: %v, want it removed", err)
	}
}

func TestServeKeepsReplacedSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "rfm.sock")
	first, err := Listen(sock, &fakeHandler{rate: 10})
	if err != nil {
		t.Fatal(err)
	}
	stopFirst := serve(t, first)

	// the path is taken over by another agent while the first one runs
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	second, err := Listen(sock, &fakeHandler{rate: 20})
	if err != nil {
		t.Fatal(err)
	}
	serve(t, second)

	stopFirst()
	st, err := (&Client{Socket: sock}).Status()
	if err != nil || st.Sampling.Rate != 20 {
		t.Fatalf("status after the first agent stopped = %+v err=%v, want the second agent", st, err)
	}
}

func TestClientWithoutAgent(t *testing.T) {
	c := &Client{Socket: filepath.Join(t.TempDir(), "missing.sock"), Timeout: 200 * time.Millisecond}
	if _, err := c.Status(); err == nil || !strings.Contains(err.Error(), "is the agent running") {
		t.Fatalf("error = %v, want a hint that the agent is not running", err)
	}
}
