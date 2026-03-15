package collector

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestRecord(t *testing.T) {
	c := New(30*time.Second, nil, 0)

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
	c := New(30*time.Second, nil, 0)
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
	c := New(10*time.Second, nil, 0)

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
	c := New(10*time.Second, nil, 0)

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

// mockReader returns pre-loaded events, then ErrDeadlineExceeded
type mockReader struct {
	events [][]byte
	idx    int
	drops  uint64
}

func (m *mockReader) ReadRawEvent() ([]byte, error) {
	if m.idx >= len(m.events) {
		return nil, os.ErrDeadlineExceeded
	}
	raw := m.events[m.idx]
	m.idx++
	return raw, nil
}

func (m *mockReader) SetDeadline(t time.Time) {}

func (m *mockReader) DroppedEvents() (uint64, error) {
	return m.drops, nil
}

func (m *mockReader) Close() error { return nil }

func TestRun(t *testing.T) {
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

	raw := encodeWireEvent(ev)
	mr := &mockReader{events: [][]byte{raw, raw, raw}}

	c := New(30*time.Second, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx, mr) }()

	// wait for all 3 events to be recorded
	deadline := time.Now().Add(time.Second)
	for c.Stats().TotalEvents < 3 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for events")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}

	s := c.Stats()
	if s.ActiveFlows != 1 {
		t.Errorf("active flows = %d, want 1", s.ActiveFlows)
	}
	if s.TotalEvents != 3 {
		t.Errorf("total events = %d, want 3", s.TotalEvents)
	}
}

func TestRunDroppedEvents(t *testing.T) {
	mr := &mockReader{drops: 42}

	c := New(30*time.Second, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx, mr) }()

	// wait for dropped events to be polled
	deadline := time.Now().Add(time.Second)
	for c.Stats().DroppedEvents == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for dropped events poll")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	<-errCh

	if s := c.Stats(); s.DroppedEvents != 42 {
		t.Fatalf("dropped events = %d, want 42", s.DroppedEvents)
	}
}

// sustainedReader always returns events, never triggers deadline exceeded
type sustainedReader struct {
	event []byte
	drops uint64
}

func (r *sustainedReader) ReadRawEvent() ([]byte, error)  { return r.event, nil }
func (r *sustainedReader) SetDeadline(t time.Time)        {}
func (r *sustainedReader) DroppedEvents() (uint64, error) { return r.drops, nil }
func (r *sustainedReader) Close() error                   { return nil }

func TestRunDroppedEventsUnderLoad(t *testing.T) {
	ev := FlowEvent{
		Ifindex: 1, Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	// reader never hits deadline — events flow continuously
	mr := &sustainedReader{event: encodeWireEvent(ev), drops: 99}

	// short timeout so the eviction ticker fires fast
	c := New(200*time.Millisecond, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx, mr) }()

	// drops must be polled via the ticker, not the deadline path
	deadline := time.Now().Add(time.Second)
	for c.Stats().DroppedEvents == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out: drops not polled under sustained traffic")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	<-errCh

	if s := c.Stats(); s.DroppedEvents != 99 {
		t.Fatalf("dropped events = %d, want 99", s.DroppedEvents)
	}
}

func TestRunContextCancel(t *testing.T) {
	mr := &mockReader{}
	c := New(30*time.Second, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := c.Run(ctx, mr)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
}

func TestStats(t *testing.T) {
	c := New(30*time.Second, nil, 0)
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

func TestMaxFlows(t *testing.T) {
	c := New(30*time.Second, nil, 2)

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
	ev3 := FlowEvent{
		Proto: 17, SrcPort: 3000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     50,
	}

	t0 := time.Now()
	c.Record(ev1, t0)
	c.Record(ev2, t0.Add(time.Second))

	// table is full (max 2), ev3 should evict oldest (ev1)
	c.Record(ev3, t0.Add(2*time.Second))

	flows := c.Flows()
	if len(flows) != 2 {
		t.Fatalf("flow count=%d want 2", len(flows))
	}
	if _, ok := flows[ev1.Key()]; ok {
		t.Fatal("oldest flow should have been evicted")
	}
	if _, ok := flows[ev2.Key()]; !ok {
		t.Fatal("ev2 should still be present")
	}
	if _, ok := flows[ev3.Key()]; !ok {
		t.Fatal("ev3 should be present")
	}
}

func TestMaxFlowsForcedEvictionStats(t *testing.T) {
	c := New(30*time.Second, nil, 1)

	ev1 := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	ev2 := FlowEvent{
		Proto: 17, SrcPort: 2000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     200,
	}

	now := time.Now()
	c.Record(ev1, now)
	c.Record(ev2, now.Add(time.Second))

	s := c.Stats()
	if s.ForcedEvictions != 1 {
		t.Fatalf("forced evictions=%d want 1", s.ForcedEvictions)
	}
}

func TestMaxFlowsZeroMeansUnlimited(t *testing.T) {
	c := New(30*time.Second, nil, 0)

	now := time.Now()
	for i := range 100 {
		ev := FlowEvent{
			Proto: 6, SrcPort: uint16(i), DstPort: 80,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			Len:     100,
		}
		c.Record(ev, now)
	}

	if len(c.Flows()) != 100 {
		t.Fatalf("flow count=%d want 100", len(c.Flows()))
	}
}
