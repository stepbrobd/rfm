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

func TestRecordCountsSegments(t *testing.T) {
	c := New(30*time.Second, nil, 0)
	now := time.Now()

	// a GRO or GSO skb carries several wire packets in one event
	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    5,
		Len:     5270,
	}
	c.Record(ev, now)

	// an event from a probe without segment accounting still counts as one
	ev.Segs = 0
	ev.Len = 100
	c.Record(ev, now)

	entry, ok := c.Flows()[ev.Key()]
	if !ok {
		t.Fatal("flow not found")
	}
	if entry.Packets != 6 {
		t.Errorf("packets=%d want 6", entry.Packets)
	}
	if entry.Bytes != 5370 {
		t.Errorf("bytes=%d want 5370", entry.Bytes)
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
	c.Evict(t0.Add(12 * time.Second))
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
	c.Evict(t0.Add(12 * time.Second))

	flows := c.Flows()
	if len(flows) != 1 {
		t.Fatalf("flow count=%d want 1", len(flows))
	}
	if _, ok := flows[fresh.Key()]; !ok {
		t.Fatal("fresh flow was evicted")
	}
}

func TestEvictUpdatedFlowKeepsFresh(t *testing.T) {
	c := New(10*time.Second, nil, 0)

	stale := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	fresh := FlowEvent{
		Proto: 17, SrcPort: 5000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.3"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.4"),
		Len:     50,
	}

	t0 := time.Now()
	c.Record(stale, t0)
	c.Record(fresh, t0.Add(time.Second))
	c.Record(stale, t0.Add(9*time.Second))

	c.Evict(t0.Add(12 * time.Second))

	flows := c.Flows()
	if len(flows) != 1 {
		t.Fatalf("flow count=%d want 1", len(flows))
	}
	if _, ok := flows[stale.Key()]; !ok {
		t.Fatal("updated flow was evicted")
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

	// wait for at least one flow to be recorded
	deadline := time.Now().Add(time.Second)
	for c.Stats().ActiveFlows < 1 {
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
}

func TestRunDroppedEvents(t *testing.T) {
	mr := &mockReader{drops: 42}

	// drops are polled by the eviction ticker, so keep its period short
	c := New(200*time.Millisecond, nil, 0)
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
	// reader never hits deadline, events flow continuously
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

func TestMaxFlowsUpdatedFlowStaysResident(t *testing.T) {
	c := New(30*time.Second, nil, 2)

	ev1 := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	ev2 := FlowEvent{
		Proto: 6, SrcPort: 2000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.3"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.4"),
		Len:     200,
	}
	ev3 := FlowEvent{
		Proto: 17, SrcPort: 3000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.5"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.6"),
		Len:     50,
	}

	t0 := time.Now()
	c.Record(ev1, t0)
	c.Record(ev2, t0.Add(time.Second))
	c.Record(ev1, t0.Add(2*time.Second))
	c.Record(ev3, t0.Add(3*time.Second))

	flows := c.Flows()
	if len(flows) != 2 {
		t.Fatalf("flow count=%d want 2", len(flows))
	}
	if _, ok := flows[ev1.Key()]; !ok {
		t.Fatal("updated flow should still be present")
	}
	if _, ok := flows[ev2.Key()]; ok {
		t.Fatal("stale flow should have been evicted")
	}
	if _, ok := flows[ev3.Key()]; !ok {
		t.Fatal("new flow should be present")
	}
}

// errorReader always returns a non-deadline error
type errorReader struct {
	err error
}

func (r *errorReader) ReadRawEvent() ([]byte, error)  { return nil, r.err }
func (r *errorReader) SetDeadline(t time.Time)        {}
func (r *errorReader) DroppedEvents() (uint64, error) { return 0, nil }
func (r *errorReader) Close() error                   { return nil }

func TestRunZeroTimeoutReturnsError(t *testing.T) {
	c := New(0, nil, 0)
	mr := &mockReader{}
	err := c.Run(context.Background(), mr)
	if err == nil {
		t.Fatal("Run with zero timeout should return error")
	}
}

func TestRunNegativeTimeoutReturnsError(t *testing.T) {
	c := New(-time.Second, nil, 0)
	mr := &mockReader{}
	err := c.Run(context.Background(), mr)
	if err == nil {
		t.Fatal("Run with negative timeout should return error")
	}
}

func TestRunReaderErrorCleansUp(t *testing.T) {
	mr := &errorReader{err: errors.New("device removed")}
	c := New(time.Second, nil, 0)

	err := c.Run(context.Background(), mr)
	if err == nil {
		t.Fatal("Run should propagate reader error")
	}
}

func TestRunRingBufErrors(t *testing.T) {
	// short garbage event that will fail DecodeFlowEvent
	mr := &mockReader{events: [][]byte{{0x00, 0x01, 0x02}}}

	c := New(30*time.Second, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx, mr) }()

	deadline := time.Now().Add(time.Second)
	for c.Stats().RingBufErrors == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for decode error to be counted")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	<-errCh

	if s := c.Stats(); s.RingBufErrors != 1 {
		t.Fatalf("decode errors = %d, want 1", s.RingBufErrors)
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

type mockFlowExporter struct {
	flows []ExportedFlow
	err   error
}

func (m *mockFlowExporter) ExportFlow(flow ExportedFlow) error {
	m.flows = append(m.flows, flow)
	return m.err
}

func TestEvictExportsExpiredFlow(t *testing.T) {
	exp := &mockFlowExporter{}
	c := New(10*time.Second, nil, 0)
	c.SetFlowExporter(exp)

	t0 := time.Now()
	ev := FlowEvent{
		Ifindex: 7,
		Dir:     0,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
		Len:     100,
	}

	c.Record(ev, t0)
	c.Evict(t0.Add(11 * time.Second))

	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows = %d, want 1", got)
	}
	flow := exp.flows[0]
	if flow.Key != ev.Key() {
		t.Fatalf("exported key = %+v, want %+v", flow.Key, ev.Key())
	}
	if flow.Entry.FirstSeen != t0 {
		t.Fatalf("first seen = %v, want %v", flow.Entry.FirstSeen, t0)
	}
	if flow.Entry.LastSeen != t0 {
		t.Fatalf("last seen = %v, want %v", flow.Entry.LastSeen, t0)
	}
	if flow.EndReason != FlowEndReasonIdleTimeout {
		t.Fatalf("end reason = %d, want %d", flow.EndReason, FlowEndReasonIdleTimeout)
	}
}

func TestRecordForcedEvictionExportsOldestFlow(t *testing.T) {
	exp := &mockFlowExporter{}
	c := New(30*time.Second, nil, 1)
	c.SetFlowExporter(exp)

	t0 := time.Now()
	ev1 := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	ev2 := FlowEvent{
		Proto: 17, SrcPort: 2000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.3"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.4"),
		Len:     50,
	}

	c.Record(ev1, t0)
	c.Record(ev2, t0.Add(time.Second))

	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows = %d, want 1", got)
	}
	if exp.flows[0].Key != ev1.Key() {
		t.Fatalf("exported key = %+v, want %+v", exp.flows[0].Key, ev1.Key())
	}
	if exp.flows[0].EndReason != FlowEndReasonLackOfResources {
		t.Fatalf("end reason = %d, want %d", exp.flows[0].EndReason, FlowEndReasonLackOfResources)
	}
	if _, ok := c.Flows()[ev2.Key()]; !ok {
		t.Fatal("new flow missing after forced eviction")
	}
}

func TestFlushExportsRemainingFlows(t *testing.T) {
	exp := &mockFlowExporter{}
	c := New(30*time.Second, nil, 0)
	c.SetFlowExporter(exp)

	t0 := time.Now()
	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}

	c.Record(ev, t0)
	c.Flush(FlowEndReasonForcedEnd)

	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows = %d, want 1", got)
	}
	if exp.flows[0].EndReason != FlowEndReasonForcedEnd {
		t.Fatalf("end reason = %d, want %d", exp.flows[0].EndReason, FlowEndReasonForcedEnd)
	}
	if len(c.Flows()) != 0 {
		t.Fatalf("flow count after flush = %d, want 0", len(c.Flows()))
	}
}

func TestExportErrorIncrementsStats(t *testing.T) {
	c := New(10*time.Second, nil, 0)
	c.SetFlowExporter(&mockFlowExporter{err: errors.New("write failed")})

	t0 := time.Now()
	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}

	c.Record(ev, t0)
	c.Evict(t0.Add(11 * time.Second))

	if s := c.Stats(); s.IPFIXErrors != 1 {
		t.Fatalf("ipfix errors = %d, want 1", s.IPFIXErrors)
	}
}

func TestEvictOrderFollowsLastSeen(t *testing.T) {
	c := New(10*time.Second, nil, 0)
	t0 := time.Now()

	mk := func(port uint16) FlowEvent {
		return FlowEvent{
			Proto: 6, SrcPort: port, DstPort: 80,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			Len:     100,
		}
	}

	// three flows, then the first one sees traffic again and becomes the
	// freshest, the eviction sweep must take the second and third only
	c.Record(mk(1), t0)
	c.Record(mk(2), t0.Add(time.Second))
	c.Record(mk(3), t0.Add(2*time.Second))
	c.Record(mk(1), t0.Add(3*time.Second))

	exp := &mockFlowExporter{}
	c.SetFlowExporter(exp)
	c.Evict(t0.Add(12*time.Second + 500*time.Millisecond))

	if got := len(exp.flows); got != 2 {
		t.Fatalf("exported flows = %d, want 2", got)
	}
	if exp.flows[0].Key.SrcPort != 2 || exp.flows[1].Key.SrcPort != 3 {
		t.Fatalf("eviction order = [%d %d], want [2 3]", exp.flows[0].Key.SrcPort, exp.flows[1].Key.SrcPort)
	}
	if _, ok := c.Flows()[mk(1).Key()]; !ok {
		t.Fatal("refreshed flow was evicted")
	}
}

func TestRecordBatchCountsEveryEvent(t *testing.T) {
	c := New(30*time.Second, nil, 0)
	t0 := time.Now()

	a := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	b := a
	b.SrcPort = 2000

	c.RecordBatch(
		[]FlowEvent{a, b, a},
		[]time.Time{t0, t0.Add(time.Millisecond), t0.Add(2 * time.Millisecond)},
	)

	flows := c.Flows()
	if len(flows) != 2 {
		t.Fatalf("flow count=%d want 2", len(flows))
	}
	if got := flows[a.Key()].Packets; got != 2 {
		t.Fatalf("packets for a=%d want 2", got)
	}
	if got := flows[a.Key()].LastSeen; !got.Equal(t0.Add(2 * time.Millisecond)) {
		t.Fatalf("last seen for a=%v want t0+2ms", got)
	}
	if got := flows[b.Key()].Packets; got != 1 {
		t.Fatalf("packets for b=%d want 1", got)
	}
}

func TestRecordBatchForcedEvictionExports(t *testing.T) {
	exp := &mockFlowExporter{}
	c := New(30*time.Second, nil, 1)
	c.SetFlowExporter(exp)
	t0 := time.Now()

	a := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	b := a
	b.SrcPort = 2000

	// with room for one flow the second event forces the first one out
	c.RecordBatch([]FlowEvent{a, b}, []time.Time{t0, t0.Add(time.Millisecond)})

	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows = %d, want 1", got)
	}
	if exp.flows[0].Key != a.Key() {
		t.Fatalf("exported key = %+v, want %+v", exp.flows[0].Key, a.Key())
	}
	if _, ok := c.Flows()[b.Key()]; !ok {
		t.Fatal("new flow missing after forced eviction")
	}
}

func TestRunRecordsBurstInOneBatch(t *testing.T) {
	ev := FlowEvent{
		Ifindex: 1, Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	raw := encodeWireEvent(ev)
	events := make([][]byte, 0, 200)
	for range 200 {
		events = append(events, raw)
	}
	mr := &mockReader{events: events}

	c := New(30*time.Second, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx, mr) }()

	deadline := time.Now().Add(time.Second)
	for {
		if f, ok := c.Flows()[ev.Key()]; ok && f.Packets == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("packets = %d, want 200", c.Flows()[ev.Key()].Packets)
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	<-errCh
}

func TestActiveTimeoutExportsIntervalRecords(t *testing.T) {
	exp := &mockFlowExporter{}
	c := New(30*time.Second, nil, 0)
	c.SetFlowExporter(exp)
	c.SetActiveTimeout(10 * time.Second)

	t0 := time.Now()
	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	c.Record(ev, t0)
	c.Record(ev, t0.Add(5*time.Second))

	// too early for the active timeout, nothing goes out
	c.Evict(t0.Add(9 * time.Second))
	if got := len(exp.flows); got != 0 {
		t.Fatalf("exported flows before the active timeout = %d, want 0", got)
	}

	// the interval record carries everything so far and the flow stays
	c.Evict(t0.Add(11 * time.Second))
	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows after the active timeout = %d, want 1", got)
	}
	first := exp.flows[0]
	if first.EndReason != FlowEndReasonActiveTimeout {
		t.Fatalf("end reason = %d, want %d", first.EndReason, FlowEndReasonActiveTimeout)
	}
	if first.Entry.Packets != 2 || first.Entry.Bytes != 200 {
		t.Fatalf("interval record = %d packets %d bytes, want 2 and 200", first.Entry.Packets, first.Entry.Bytes)
	}
	if !first.Entry.FirstSeen.Equal(t0) || !first.Entry.LastSeen.Equal(t0.Add(5*time.Second)) {
		t.Fatalf("interval = %v..%v, want t0..t0+5s", first.Entry.FirstSeen, first.Entry.LastSeen)
	}
	if _, ok := c.Flows()[ev.Key()]; !ok {
		t.Fatal("flow left the table on an active export")
	}
	if got := c.Flows()[ev.Key()].Packets; got != 2 {
		t.Fatalf("live packets = %d, want the cumulative 2", got)
	}

	// a quiet flow produces no second interval record
	c.Evict(t0.Add(22 * time.Second))
	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows after a quiet interval = %d, want 1", got)
	}

	// more traffic, then idle eviction exports only the remainder with the
	// interval starting at the previous sweep
	c.Record(ev, t0.Add(25*time.Second))
	c.Evict(t0.Add(60 * time.Second))
	if got := len(exp.flows); got != 2 {
		t.Fatalf("exported flows after eviction = %d, want 2", got)
	}
	last := exp.flows[1]
	if last.EndReason != FlowEndReasonIdleTimeout {
		t.Fatalf("end reason = %d, want %d", last.EndReason, FlowEndReasonIdleTimeout)
	}
	if last.Entry.Packets != 1 || last.Entry.Bytes != 100 {
		t.Fatalf("final record = %d packets %d bytes, want 1 and 100", last.Entry.Packets, last.Entry.Bytes)
	}
	if !last.Entry.FirstSeen.Equal(t0.Add(22 * time.Second)) {
		t.Fatalf("final interval start = %v, want the previous sweep at t0+22s", last.Entry.FirstSeen)
	}
}

func TestEvictSkipsFullyExportedFlow(t *testing.T) {
	exp := &mockFlowExporter{}
	c := New(30*time.Second, nil, 0)
	c.SetFlowExporter(exp)
	c.SetActiveTimeout(10 * time.Second)

	t0 := time.Now()
	ev := FlowEvent{
		Proto: 17, SrcPort: 5000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     60,
	}
	c.Record(ev, t0)
	c.Evict(t0.Add(11 * time.Second))
	c.Flush(FlowEndReasonForcedEnd)

	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows = %d, want 1 (no empty record at flush)", got)
	}
}

func TestSampleRateScalesEstimatesAtRecordTime(t *testing.T) {
	c := New(30*time.Second, nil, 0)
	c.SetSampleRate(10, 0)
	now := time.Now()

	ev := FlowEvent{
		Tstamp: 1_000,
		Proto:  6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     100,
	}
	c.Record(ev, now)

	// the rate doubles from boot time 5000 on, an older event still scales
	// by 10 and a newer one by 20
	c.SetSampleRate(20, 5_000)
	if got := c.SampleRate(); got != 20 {
		t.Fatalf("current rate = %d, want 20", got)
	}
	late := ev
	late.Tstamp = 6_000
	c.Record(late, now)
	early := ev
	early.Tstamp = 2_000
	c.Record(early, now)

	entry := c.Flows()[ev.Key()]
	if entry.Packets != 3 || entry.Bytes != 300 {
		t.Fatalf("sampled = %d packets %d bytes, want 3 and 300", entry.Packets, entry.Bytes)
	}
	if entry.EstPackets != 40 || entry.EstBytes != 4000 {
		t.Fatalf("estimated = %d packets %d bytes, want 40 and 4000", entry.EstPackets, entry.EstBytes)
	}
	if got := entry.SamplingProbability(); got < 0.074 || got > 0.076 {
		t.Fatalf("sampling probability = %v, want 3/40", got)
	}
}

func TestExportedRecordCarriesEstimateDelta(t *testing.T) {
	exp := &mockFlowExporter{}
	c := New(30*time.Second, nil, 0)
	c.SetFlowExporter(exp)
	c.SetSampleRate(100, 0)

	t0 := time.Now()
	ev := FlowEvent{
		Proto: 17, SrcPort: 5000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Len:     60,
	}
	c.Record(ev, t0)
	c.Evict(t0.Add(time.Minute))

	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows = %d, want 1", got)
	}
	rec := exp.flows[0].Entry
	if rec.Packets != 1 || rec.EstPackets != 100 || rec.EstBytes != 6000 {
		t.Fatalf("record = %+v, want 1 sampled packet standing for 100 packets and 6000 bytes", rec)
	}
	if got := rec.SamplingProbability(); got != 0.01 {
		t.Fatalf("sampling probability = %v, want 0.01", got)
	}
}
