package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ysun.co/rfm/ctl"
)

// fakeControl stands in for the running agent behind the socket
type fakeControl struct {
	rate uint32
}

func (f *fakeControl) Status() ctl.Status {
	return ctl.Status{
		Version:    "test",
		Uptime:     time.Minute,
		Interfaces: []ctl.Interface{{Name: "eth0", Ifindex: 2}},
		Sampling:   ctl.Sampling{Rate: f.rate, Base: 10, Max: 1000},
		Flows:      ctl.Flows{Active: 3, Max: 65536},
	}
}

func (f *fakeControl) FlowsTop(n int, by string) []ctl.FlowRow {
	rows := []ctl.FlowRow{
		{Interface: "eth0", Direction: "ingress", Proto: 6, Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), SrcPort: 1, DstPort: 443, EstBytes: 9000, EstPackets: 9, SrcASN: 64500, FirstSeen: time.Now()},
		{Interface: "eth0", Direction: "egress", Proto: 17, Src: netip.MustParseAddr("10.0.0.2"), Dst: netip.MustParseAddr("10.0.0.1"), SrcPort: 53, DstPort: 2, EstBytes: 100, EstPackets: 50, FirstSeen: time.Now()},
	}
	if by == "packets" {
		rows[0], rows[1] = rows[1], rows[0]
	}
	if n < len(rows) {
		rows = rows[:n]
	}
	return rows
}

func (f *fakeControl) FlowsCount() uint64 { return 2 }

func (f *fakeControl) RIBLookup(addr netip.Addr) (ctl.Route, bool, error) {
	if addr != netip.MustParseAddr("203.0.113.9") {
		return ctl.Route{}, false, nil
	}
	return ctl.Route{
		Prefix:      netip.MustParsePrefix("203.0.113.0/24"),
		OriginASN:   64496,
		ASPath:      []uint32{64501, 64496},
		Communities: []string{"64501:100"},
		PeerASN:     64501,
		PeerAddress: netip.MustParseAddr("192.0.2.2"),
		PostPolicy:  true,
	}, true, nil
}

func (f *fakeControl) RIBSummary() (ctl.RIB, error) {
	return ctl.RIB{Listen: "[::1]:11019", PrefixesV4: 12, PrefixesV6: 3, Routes: 15, Peers: 1}, nil
}

func (f *fakeControl) SetSampleRate(rate uint32) error {
	if rate > 1000 {
		return errors.New("rate above max_sample_rate")
	}
	f.rate = rate
	return nil
}

func (f *fakeControl) ConfigShow() string { return "[agent]\ninterfaces = [\"eth0\"]\n" }

func (f *fakeControl) ReloadMMDB() error { return nil }

// runCLI executes the rfm command line against the fake agent and returns
// what it printed
func runCLI(t *testing.T, sock string, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append(args, "--socket", sock))
	err := root.Execute()
	return out.String(), err
}

func startFakeAgent(t *testing.T) (string, *fakeControl) {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "rfm.sock")
	h := &fakeControl{rate: 10}
	srv, err := ctl.Listen(sock, h)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		ctlJSON = false
	})
	return sock, h
}

func TestCLIStatus(t *testing.T) {
	sock, _ := startFakeAgent(t)

	out, err := runCLI(t, sock, "status")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	for _, want := range []string{"version     test", "interfaces  eth0", "1 in 10", "3 active of 65536"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}

	out, err = runCLI(t, sock, "status", "--json")
	if err != nil {
		t.Fatalf("status --json: %v", err)
	}
	if !strings.Contains(out, `"rate": 10`) || !strings.Contains(out, `"version": "test"`) {
		t.Fatalf("json output unexpected:\n%s", out)
	}
}

func TestCLIFlows(t *testing.T) {
	sock, _ := startFakeAgent(t)

	out, err := runCLI(t, sock, "flows", "top", "1", "--by", "packets")
	if err != nil {
		t.Fatalf("flows top: %v\n%s", err, out)
	}
	if !strings.Contains(out, "10.0.0.2:53") || strings.Contains(out, "10.0.0.1:1") {
		t.Fatalf("top by packets should list only the 50 packet flow:\n%s", out)
	}
	if !strings.Contains(out, "IFACE") || !strings.Contains(out, "egress") {
		t.Fatalf("table header or direction missing:\n%s", out)
	}

	if _, err := runCLI(t, sock, "flows", "top", "0"); err == nil {
		t.Fatal("flows top 0 must be rejected")
	}
	if _, err := runCLI(t, sock, "flows", "top", "--by", "colour"); err == nil {
		t.Fatal("flows top --by colour must be rejected")
	}

	out, err = runCLI(t, sock, "flows", "count")
	if err != nil || strings.TrimSpace(out) != "2" {
		t.Fatalf("flows count = %q err=%v, want 2", out, err)
	}
}

func TestCLIRIB(t *testing.T) {
	sock, _ := startFakeAgent(t)

	out, err := runCLI(t, sock, "rib", "lookup", "203.0.113.9")
	if err != nil {
		t.Fatalf("rib lookup: %v\n%s", err, out)
	}
	for _, want := range []string{"prefix       203.0.113.0/24", "origin       64496", "as path      64501 64496", "communities  64501:100", "192.0.2.2 AS64501 (post policy)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rib lookup output missing %q:\n%s", want, out)
		}
	}
	if _, err := runCLI(t, sock, "rib", "lookup", "192.0.2.1"); err == nil || !strings.Contains(err.Error(), "no route") {
		t.Fatalf("missing route error = %v", err)
	}
	if _, err := runCLI(t, sock, "rib", "lookup", "not-an-address"); err == nil {
		t.Fatal("bad address must be rejected")
	}

	out, err = runCLI(t, sock, "rib", "summary")
	if err != nil || !strings.Contains(out, "12 ipv4 and 3 ipv6 prefixes, 15 routes from 1 peers") {
		t.Fatalf("rib summary = %q err=%v", out, err)
	}
}

func TestCLISetSampleRate(t *testing.T) {
	sock, h := startFakeAgent(t)

	out, err := runCLI(t, sock, "set", "sample-rate", "40")
	if err != nil || !strings.Contains(out, "sampling 1 in 40") || h.rate != 40 {
		t.Fatalf("set sample-rate: out=%q err=%v rate=%d", out, err, h.rate)
	}
	if _, err := runCLI(t, sock, "set", "sample-rate", "0"); err == nil {
		t.Fatal("rate 0 must be rejected before reaching the agent")
	}
	if _, err := runCLI(t, sock, "set", "sample-rate", "5000"); err == nil || !strings.Contains(err.Error(), "above max_sample_rate") {
		t.Fatalf("agent error must surface: %v", err)
	}
}

func TestCLIConfigAndReload(t *testing.T) {
	sock, _ := startFakeAgent(t)

	out, err := runCLI(t, sock, "config", "show")
	if err != nil || !strings.Contains(out, `interfaces = ["eth0"]`) {
		t.Fatalf("config show = %q err=%v", out, err)
	}
	out, err = runCLI(t, sock, "reload", "mmdb")
	if err != nil || strings.TrimSpace(out) != "reloaded" {
		t.Fatalf("reload mmdb = %q err=%v", out, err)
	}
}

func TestCLIWithoutAgent(t *testing.T) {
	_, err := runCLI(t, filepath.Join(t.TempDir(), "none.sock"), "status")
	if err == nil || !strings.Contains(err.Error(), "is the agent running") {
		t.Fatalf("error = %v, want a hint that the agent is not running", err)
	}
}
