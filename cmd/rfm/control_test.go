package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
	"ysun.co/rfm/ctl"
)

func testHandler(t *testing.T) (*controlHandler, *collector.Collector) {
	t.Helper()
	c := collector.New(30*time.Second, nil, 0)
	c.SetSampleRate(10, 0)
	cfg := &config.Config{}
	cfg.Agent.BPF.SampleRate = 10
	cfg.Agent.BPF.MaxSampleRate = 1000
	cfg.Agent.Collector.MaxFlows = 65536
	return &controlHandler{started: time.Now(), cfg: cfg, cfgText: "[agent]\n", col: c}, c
}

func TestControlFlowsTopOrdersAndLimits(t *testing.T) {
	h, c := testHandler(t)
	now := time.Now()
	mk := func(port uint16, n int, size uint32) {
		ev := collector.FlowEvent{
			Ifindex: 1, Proto: 6, SrcPort: port, DstPort: 443,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			Len:     size,
		}
		for range n {
			c.Record(ev, now)
		}
	}
	mk(1, 1, 5000) // most bytes
	mk(2, 5, 100)  // most packets
	mk(3, 2, 200)

	rows := h.FlowsTop(2, "bytes")
	if len(rows) != 2 || rows[0].SrcPort != 1 || rows[1].SrcPort != 2 {
		t.Fatalf("top by bytes = %+v", rows)
	}
	if rows[0].EstBytes != 50000 || rows[0].Packets != 1 {
		t.Fatalf("row = %+v, want 50000 estimated bytes from 1 sampled packet", rows[0])
	}
	rows = h.FlowsTop(10, "packets")
	if len(rows) != 3 || rows[0].SrcPort != 2 || rows[0].EstPackets != 50 {
		t.Fatalf("top by packets = %+v", rows)
	}
	if h.FlowsCount() != 3 {
		t.Fatalf("count = %d, want 3", h.FlowsCount())
	}
}

func TestControlStatusWithoutOptionalBackends(t *testing.T) {
	h, _ := testHandler(t)
	st := h.Status()
	if st.Sampling.Rate != 10 || st.Sampling.Max != 1000 || st.Flows.Max != 65536 {
		t.Fatalf("status = %+v", st)
	}
	if st.IPFIX != nil || st.MMDB != nil || st.RIB != nil {
		t.Fatalf("optional sections must be nil without backends: %+v", st)
	}
	if _, err := h.RIBSummary(); err == nil {
		t.Fatal("rib summary without a rib must fail")
	}
	if _, _, err := h.RIBLookup(netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Fatal("rib lookup without a rib must fail")
	}
	if err := h.ReloadMMDB(); err == nil {
		t.Fatal("mmdb reload without mmdb must fail")
	}
	if h.ConfigShow() != "[agent]\n" {
		t.Fatalf("config show = %q", h.ConfigShow())
	}
}

func TestControlSetSampleRate(t *testing.T) {
	h, c := testHandler(t)
	var probe []uint32
	c.SetRateController(10, 1000, func(n uint32) error {
		probe = append(probe, n)
		return nil
	})

	if err := h.SetSampleRate(5000); err == nil || !strings.Contains(err.Error(), "above max_sample_rate") {
		t.Fatalf("rate 5000 = %v, want it refused above max_sample_rate", err)
	}
	if len(probe) != 0 {
		t.Fatalf("a refused rate reached the probe: %v", probe)
	}

	if err := h.SetSampleRate(40); err != nil {
		t.Fatalf("rate 40: %v", err)
	}
	if len(probe) != 1 || probe[0] != 40 || c.SampleRate() != 40 || h.Status().Sampling.Rate != 40 {
		t.Fatalf("probe %v collector %d, want both at 40", probe, c.SampleRate())
	}
}

func TestCLISetSampleRateAgainstTheAgent(t *testing.T) {
	h, c := testHandler(t)
	c.SetRateApplier(func(uint32) error { return nil })

	sock := filepath.Join(t.TempDir(), "rfm.sock")
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
	})

	out, err := runCLI(t, sock, "set", "sample-rate", "40")
	if err != nil || !strings.Contains(out, "sampling 1 in 40") || c.SampleRate() != 40 {
		t.Fatalf("set sample-rate 40: out=%q err=%v rate=%d", out, err, c.SampleRate())
	}
	if _, err := runCLI(t, sock, "set", "sample-rate", "5000"); err == nil || !strings.Contains(err.Error(), "above max_sample_rate") {
		t.Fatalf("set sample-rate 5000: %v, want above max_sample_rate", err)
	}
	if got := c.SampleRate(); got != 40 {
		t.Fatalf("rate = %d after a refused change, want 40", got)
	}
}

func TestPrintStatus(t *testing.T) {
	var b strings.Builder
	printStatus(&b, ctl.Status{
		Version:    "2026.902.0",
		Uptime:     90 * time.Second,
		Interfaces: []ctl.Interface{{Name: "eth0", Ifindex: 2}},
		Sampling:   ctl.Sampling{Rate: 20, Base: 10, Max: 1000, Adaptive: true},
		Flows:      ctl.Flows{Active: 12, Max: 65536},
		IPFIX:      &ctl.IPFIX{Collector: "[::1]:4739", Connected: true, Messages: 3, Records: 40, SendErrors: map[string]uint64{"EPERM": 2}},
		MMDB:       &ctl.MMDB{ASNBuildEpoch: 1_700_000_000},
	})
	out := b.String()
	for _, want := range []string{"1 in 20 (adaptive, base 10, max 1000)", "12 active of 65536", "[::1]:4739 connected", "EPERM=2", "asn 2023-11-14, city none"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}
