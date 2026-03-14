package collector

import (
	"net/netip"
	"testing"
	"time"
)

func TestRecord(t *testing.T) {
	c := New(30 * time.Second)

	ev := FlowEvent{
		Ifindex: 1,
		Dir:     0,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
		Len:     100,
	}

	now := time.Now()
	c.Record(ev, now)
	c.Record(ev, now)

	flows := c.Flows()
	key := ev.Key()
	entry, ok := flows[key]
	if !ok {
		t.Fatal("flow not found")
	}
	if entry.Packets != 2 {
		t.Errorf("packets=%d want 2", entry.Packets)
	}
	if entry.Bytes != 200 {
		t.Errorf("bytes=%d want 200", entry.Bytes)
	}
}

func TestRecordDistinctFlows(t *testing.T) {
	c := New(30 * time.Second)
	now := time.Now()

	ev1 := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	ev2 := FlowEvent{
		Proto: 6, SrcPort: 2000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     200,
	}

	c.Record(ev1, now)
	c.Record(ev2, now)

	flows := c.Flows()
	if len(flows) != 2 {
		t.Fatalf("flow count=%d want 2", len(flows))
	}
}

func TestEvict(t *testing.T) {
	c := New(10 * time.Second)

	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}

	t0 := time.Now()
	c.Record(ev, t0)

	// before timeout: flow should survive
	c.Evict(t0.Add(5 * time.Second))
	if len(c.Flows()) != 1 {
		t.Fatal("flow evicted too early")
	}

	// after timeout: flow should be evicted
	c.Evict(t0.Add(11 * time.Second))
	if len(c.Flows()) != 0 {
		t.Fatal("stale flow not evicted")
	}
}

func TestEvictKeepsFresh(t *testing.T) {
	c := New(10 * time.Second)

	stale := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	fresh := FlowEvent{
		Proto: 17, SrcPort: 5000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     50,
	}

	t0 := time.Now()
	c.Record(stale, t0)
	c.Record(fresh, t0.Add(8*time.Second))

	// at t0+11s: stale should be evicted, fresh should remain
	c.Evict(t0.Add(11 * time.Second))

	flows := c.Flows()
	if len(flows) != 1 {
		t.Fatalf("flow count=%d want 1", len(flows))
	}
	if _, ok := flows[fresh.Key()]; !ok {
		t.Fatal("fresh flow was evicted")
	}
}

func TestStats(t *testing.T) {
	c := New(30 * time.Second)
	now := time.Now()

	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}

	c.Record(ev, now)
	c.Record(ev, now)

	s := c.Stats()
	if s.ActiveFlows != 1 {
		t.Errorf("active flows=%d want 1", s.ActiveFlows)
	}
	if s.TotalEvents != 2 {
		t.Errorf("total events=%d want 2", s.TotalEvents)
	}
}
