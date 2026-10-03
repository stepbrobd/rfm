package collector

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ysun.co/rfm/config"
)

func TestRecord(t *testing.T) {
	c := New(30*time.Second, nil, config.DefaultMaxFlows)

	ev := FlowEvent{
		Ifindex: 1,
		Dir:     0,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
		Segs:    1,
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
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
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

	ev.Segs = 1
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
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	now := time.Now()

	ev1 := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	ev2 := FlowEvent{
		Proto: 6, SrcPort: 2000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
	c := New(10*time.Second, nil, config.DefaultMaxFlows)

	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
	c := New(10*time.Second, nil, config.DefaultMaxFlows)

	stale := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	fresh := FlowEvent{
		Proto: 17, SrcPort: 5000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
	c := New(10*time.Second, nil, config.DefaultMaxFlows)

	stale := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	fresh := FlowEvent{
		Proto: 17, SrcPort: 5000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.3"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.4"),
		Segs:    1,
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
		Segs:    1,
		Len:     100,
	}

	raw := encodeWireEvent(ev)
	mr := &mockReader{events: [][]byte{raw, raw, raw}}

	c := New(30*time.Second, nil, config.DefaultMaxFlows)
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
	c := New(200*time.Millisecond, nil, config.DefaultMaxFlows)
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
		Segs:    1,
		Len:     100,
	}
	// reader never hits deadline, events flow continuously
	mr := &sustainedReader{event: encodeWireEvent(ev), drops: 99}

	// short timeout so the eviction ticker fires fast
	c := New(200*time.Millisecond, nil, config.DefaultMaxFlows)
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
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := c.Run(ctx, mr)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
}

func TestStats(t *testing.T) {
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	now := time.Now()

	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
		Segs:    1,
		Len:     100,
	}
	ev2 := FlowEvent{
		Proto: 6, SrcPort: 2000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     200,
	}
	ev3 := FlowEvent{
		Proto: 17, SrcPort: 3000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
		Segs:    1,
		Len:     100,
	}
	ev2 := FlowEvent{
		Proto: 17, SrcPort: 2000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
		Segs:    1,
		Len:     100,
	}
	ev2 := FlowEvent{
		Proto: 6, SrcPort: 2000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.3"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.4"),
		Segs:    1,
		Len:     200,
	}
	ev3 := FlowEvent{
		Proto: 17, SrcPort: 3000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.5"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.6"),
		Segs:    1,
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
	c := New(0, nil, config.DefaultMaxFlows)
	mr := &mockReader{}
	err := c.Run(context.Background(), mr)
	if err == nil {
		t.Fatal("Run with zero timeout should return error")
	}
}

func TestRunWithoutRoomForAFlowReturnsError(t *testing.T) {
	c := New(30*time.Second, nil, 0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Run(ctx, &mockReader{}); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run with max flows 0 returned %v, want it refused", err)
	}
}

func TestRunNegativeTimeoutReturnsError(t *testing.T) {
	c := New(-time.Second, nil, config.DefaultMaxFlows)
	mr := &mockReader{}
	err := c.Run(context.Background(), mr)
	if err == nil {
		t.Fatal("Run with negative timeout should return error")
	}
}

func TestRunReaderErrorCleansUp(t *testing.T) {
	mr := &errorReader{err: errors.New("device removed")}
	c := New(time.Second, nil, config.DefaultMaxFlows)

	err := c.Run(context.Background(), mr)
	if err == nil {
		t.Fatal("Run should propagate reader error")
	}
}

func TestRunRingBufErrors(t *testing.T) {
	// a short garbage event and one whose l2 headers do not fit its wire
	// bytes both fail DecodeFlowEvent
	malformed := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    2, Len: 20, L2Len: 14,
	}
	mr := &mockReader{events: [][]byte{{0x00, 0x01, 0x02}, encodeWireEvent(malformed)}}

	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx, mr) }()

	deadline := time.Now().Add(time.Second)
	for c.Stats().RingBufErrors < 2 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for decode errors to be counted")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	<-errCh

	if s := c.Stats(); s.RingBufErrors != 2 || s.ActiveFlows != 0 {
		t.Fatalf("decode errors = %d with %d flows, want 2 and none recorded", s.RingBufErrors, s.ActiveFlows)
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

// recordKey returns the key of the flow a record belongs to
func recordKey(f ExportedFlow) FlowKey {
	return FlowKey{
		Ifindex: f.Ifindex,
		Dir:     f.Dir,
		Proto:   f.Proto,
		SrcAddr: netip.AddrFrom16(f.SrcAddr),
		DstAddr: netip.AddrFrom16(f.DstAddr),
		SrcPort: f.SrcPort,
		DstPort: f.DstPort,
	}
}

// firstSeen returns the time of the first packet a record carries
func firstSeen(f ExportedFlow) time.Time {
	return time.Unix(0, f.Start)
}

// lastSeen returns the time of the last packet a record carries
func lastSeen(f ExportedFlow) time.Time {
	return time.Unix(0, f.End)
}

func TestEvictExportsExpiredFlow(t *testing.T) {
	exp := &mockFlowExporter{}
	c := New(10*time.Second, nil, config.DefaultMaxFlows)
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
		Segs:    1,
		Len:     100,
	}

	c.Record(ev, t0)
	c.Evict(t0.Add(11 * time.Second))

	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows = %d, want 1", got)
	}
	flow := exp.flows[0]
	if recordKey(flow) != ev.Key() {
		t.Fatalf("exported key = %+v, want %+v", recordKey(flow), ev.Key())
	}
	if !firstSeen(flow).Equal(t0) {
		t.Fatalf("first seen = %v, want %v", firstSeen(flow), t0)
	}
	if !lastSeen(flow).Equal(t0) {
		t.Fatalf("last seen = %v, want %v", lastSeen(flow), t0)
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
		Segs:    1,
		Len:     100,
	}
	ev2 := FlowEvent{
		Proto: 17, SrcPort: 2000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.3"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.4"),
		Segs:    1,
		Len:     50,
	}

	c.Record(ev1, t0)
	c.Record(ev2, t0.Add(time.Second))

	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows = %d, want 1", got)
	}
	if recordKey(exp.flows[0]) != ev1.Key() {
		t.Fatalf("exported key = %+v, want %+v", recordKey(exp.flows[0]), ev1.Key())
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
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetFlowExporter(exp)

	t0 := time.Now()
	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
	c := New(10*time.Second, nil, config.DefaultMaxFlows)
	c.SetFlowExporter(&mockFlowExporter{err: errors.New("write failed")})

	t0 := time.Now()
	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}

	c.Record(ev, t0)
	c.Evict(t0.Add(11 * time.Second))

	if s := c.Stats(); s.IPFIXErrors != 1 {
		t.Fatalf("ipfix errors = %d, want 1", s.IPFIXErrors)
	}
}

func TestEvictOrderFollowsLastSeen(t *testing.T) {
	c := New(10*time.Second, nil, config.DefaultMaxFlows)
	t0 := time.Now()

	mk := func(port uint16) FlowEvent {
		return FlowEvent{
			Proto: 6, SrcPort: port, DstPort: 80,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			Segs:    1,
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
	if exp.flows[0].SrcPort != 2 || exp.flows[1].SrcPort != 3 {
		t.Fatalf("eviction order = [%d %d], want [2 3]", exp.flows[0].SrcPort, exp.flows[1].SrcPort)
	}
	if _, ok := c.Flows()[mk(1).Key()]; !ok {
		t.Fatal("refreshed flow was evicted")
	}
}

func TestRecordBatchCountsEveryEvent(t *testing.T) {
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	t0 := time.Now()

	a := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
		Segs:    1,
		Len:     100,
	}
	b := a
	b.SrcPort = 2000

	// with room for one flow the second event forces the first one out
	c.RecordBatch([]FlowEvent{a, b}, []time.Time{t0, t0.Add(time.Millisecond)})

	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows = %d, want 1", got)
	}
	if recordKey(exp.flows[0]) != a.Key() {
		t.Fatalf("exported key = %+v, want %+v", recordKey(exp.flows[0]), a.Key())
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
		Segs:    1,
		Len:     100,
	}
	raw := encodeWireEvent(ev)
	events := make([][]byte, 0, 200)
	for range 200 {
		events = append(events, raw)
	}
	mr := &mockReader{events: events}

	c := New(30*time.Second, nil, config.DefaultMaxFlows)
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
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetFlowExporter(exp)
	c.SetActiveTimeout(10 * time.Second)

	t0 := time.Now()
	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
	if first.Packets != 2 || first.Octets != 200 {
		t.Fatalf("interval record = %d packets %d octets, want 2 and 200", first.Packets, first.Octets)
	}
	if !firstSeen(first).Equal(t0) || !lastSeen(first).Equal(t0.Add(5*time.Second)) {
		t.Fatalf("interval = %v..%v, want t0..t0+5s", firstSeen(first), lastSeen(first))
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

	// more traffic, then idle eviction exports only the remainder over the
	// events it carries
	c.Record(ev, t0.Add(25*time.Second))
	c.Evict(t0.Add(60 * time.Second))
	if got := len(exp.flows); got != 2 {
		t.Fatalf("exported flows after eviction = %d, want 2", got)
	}
	last := exp.flows[1]
	if last.EndReason != FlowEndReasonIdleTimeout {
		t.Fatalf("end reason = %d, want %d", last.EndReason, FlowEndReasonIdleTimeout)
	}
	if last.Packets != 1 || last.Octets != 100 {
		t.Fatalf("final record = %d packets %d octets, want 1 and 100", last.Packets, last.Octets)
	}
	if !firstSeen(last).Equal(t0.Add(25*time.Second)) || !lastSeen(last).Equal(t0.Add(25*time.Second)) {
		t.Fatalf("final interval = %v..%v, want the one event at t0+25s", firstSeen(last), lastSeen(last))
	}
}

func TestIntervalRecordsSpanTheirEvents(t *testing.T) {
	exp := &mockFlowExporter{}
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetFlowExporter(exp)
	c.SetActiveTimeout(60 * time.Second)

	t0 := time.Unix(1_700_000_000, 0)
	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	// events from different cpus reach the collector slightly out of order
	c.Record(ev, t0.Add(time.Second))
	c.Record(ev, t0)
	c.Record(ev, t0.Add(10*time.Second))
	c.Record(ev, t0.Add(9*time.Second))
	if got := c.Flows()[ev.Key()]; !got.FirstSeen.Equal(t0) || !got.LastSeen.Equal(t0.Add(10*time.Second)) {
		t.Fatalf("flow spans %v..%v, want the earliest and latest events t0..t0+10s", got.FirstSeen, got.LastSeen)
	}
	c.Record(ev, t0.Add(59*time.Second))

	// the sweep marks the flow at its tick, then an event sampled before the
	// tick is consumed after it
	c.Evict(t0.Add(61 * time.Second))
	late := t0.Add(60*time.Second + 950*time.Millisecond)
	c.Record(ev, late)
	c.Evict(t0.Add(121 * time.Second))

	if got := len(exp.flows); got != 2 {
		t.Fatalf("exported flows = %d, want 2", got)
	}
	for i, f := range exp.flows {
		if f.End < f.Start {
			t.Errorf("record %d ends at %v before it starts at %v", i, lastSeen(f), firstSeen(f))
		}
	}
	if first := exp.flows[0]; !firstSeen(first).Equal(t0) || !lastSeen(first).Equal(t0.Add(59*time.Second)) {
		t.Errorf("active record spans %v..%v, want t0..t0+59s", firstSeen(first), lastSeen(first))
	}
	if last := exp.flows[1]; !firstSeen(last).Equal(late) || !lastSeen(last).Equal(late) {
		t.Errorf("idle record spans %v..%v, want the late event alone at %v", firstSeen(last), lastSeen(last), late)
	}
}

func TestSweepSendsIntervalRecordsAtTheSweepNearestTheirActiveTimeout(t *testing.T) {
	const period = 10 * time.Second
	t0 := time.Unix(1_700_000_000, 0)
	a := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	b := a
	b.SrcPort = 2000
	newCollector := func() (*Collector, *mockFlowExporter) {
		exp := &mockFlowExporter{}
		c := New(30*time.Second, nil, config.DefaultMaxFlows)
		c.SetFlowExporter(exp)
		c.SetActiveTimeout(period)
		return c, exp
	}

	// ticks come a few microseconds off their schedule either way, a flow
	// marked at one sweep is due at the next also when its tick is early
	c, exp := newCollector()
	c.Record(a, t0)
	c.sweep(t0.Add(period), period)
	c.Record(a, t0.Add(period+period/2))
	c.sweep(t0.Add(2*period-time.Microsecond), period)
	if got := len(exp.flows); got != 2 {
		t.Fatalf("records after a tick a microsecond early = %d, want 2", got)
	}

	// a flow created between a tick and its sweep sits ahead of the flows the
	// sweep marks, a millisecond short of its own active timeout at the next
	// sweep it must not hold them back
	c, exp = newCollector()
	c.Record(a, t0)
	c.Record(b, t0.Add(period+time.Millisecond))
	c.sweep(t0.Add(period), period)
	c.Record(a, t0.Add(period+period/2))
	c.sweep(t0.Add(2*period), period)
	if got := len(exp.flows); got != 3 {
		t.Fatalf("records = %d, want two of the flow the first sweep marked and one of the newer flow", got)
	}
}

func TestSweepsKeepIntervalRecordsOneActiveTimeoutApart(t *testing.T) {
	const eviction = 30 * time.Second
	t0 := time.Unix(1_700_000_000, 0)
	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	// active timeouts below, at and past half the eviction timeout, among
	// them ones no multiple of it and one no sweep period divides to the
	// nanosecond
	for _, active := range []time.Duration{5 * time.Second, 15 * time.Second, 20 * time.Second, 40 * time.Second, 50 * time.Second, 60 * time.Second} {
		period := sweepPeriod(eviction, active)
		if period > eviction/2 {
			t.Fatalf("active timeout %v: sweeps every %v, want at most half the eviction timeout", active, period)
		}
		exp := &mockFlowExporter{}
		c := New(eviction, nil, config.DefaultMaxFlows)
		c.SetFlowExporter(exp)
		c.SetActiveTimeout(active)

		// the flow sees a packet before every sweep
		var sent []time.Duration
		for now := t0; now.Sub(t0) < 3*active+period/2; now = now.Add(period) {
			c.Record(ev, now)
			c.sweep(now, period)
			if len(exp.flows) > len(sent) {
				sent = append(sent, now.Sub(t0).Round(time.Millisecond))
			}
		}
		want := []time.Duration{active, 2 * active, 3 * active}
		if !slices.Equal(sent, want) {
			t.Fatalf("active timeout %v, sweeps every %v: interval records at %v, want %v", active, period, sent, want)
		}
	}
}

// idleReader has no events and waits a little on every read like a blocking
// ring buffer read would, so Run does not spin
type idleReader struct{}

func (idleReader) ReadRawEvent() ([]byte, error) {
	time.Sleep(time.Millisecond)
	return nil, os.ErrDeadlineExceeded
}
func (idleReader) SetDeadline(time.Time)          {}
func (idleReader) DroppedEvents() (uint64, error) { return 0, nil }
func (idleReader) Close() error                   { return nil }

// sweepCounter stands in for the ring buffer and the exporter of Run, it has
// no events, counts the sweeps by their poll of the drop counter, which comes
// after their exports, and hands the sweep of every interval record to a
// channel, safe for the Run goroutines
type sweepCounter struct {
	idleReader
	sweeps  atomic.Uint64
	records chan uint64
}

func (s *sweepCounter) DroppedEvents() (uint64, error) {
	s.sweeps.Add(1)
	return 0, nil
}

func (s *sweepCounter) ExportFlow(flow ExportedFlow) error {
	if flow.EndReason == FlowEndReasonActiveTimeout {
		s.records <- s.sweeps.Load()
	}
	return nil
}

func TestRunHonorsActiveTimeoutBelowHalfTheEvictionTimeout(t *testing.T) {
	sc := &sweepCounter{records: make(chan uint64, 16)}
	// half the eviction timeout is 5s, the active timeout is far shorter
	c := New(10*time.Second, nil, config.DefaultMaxFlows)
	c.SetFlowExporter(sc)
	c.SetActiveTimeout(50 * time.Millisecond)

	ev := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	c.Record(ev, time.Now())

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx, sc) }()
	// the flow keeps going with a packet every millisecond
	traffic := make(chan struct{})
	go func() {
		defer close(traffic)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				c.Record(ev, now)
			}
		}
	}()
	defer func() {
		cancel()
		<-traffic
		<-errCh
	}()

	// the sweep runs at the active timeout, so every sweep sends an interval
	// record, also the ones whose tick comes a few microseconds short of a
	// period after the tick before
	var last uint64
	for i := range 10 {
		select {
		case sweep := <-sc.records:
			if i > 0 && sweep != last+1 {
				t.Fatalf("interval records %d and %d are %d sweeps apart, want one active timeout", i, i+1, sweep-last)
			}
			last = sweep
		case <-time.After(2 * time.Second):
			t.Fatal("no interval record within 2s although the active timeout is 50ms")
		}
	}
}

// blockingExporter holds the first export until released
type blockingExporter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (e *blockingExporter) ExportFlow(ExportedFlow) error {
	e.once.Do(func() { close(e.entered) })
	<-e.release
	return nil
}

func TestRunWaitsForItsSweep(t *testing.T) {
	exp := &blockingExporter{entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(exp.release) }) }
	defer release()

	c := New(20*time.Millisecond, nil, config.DefaultMaxFlows)
	c.SetFlowExporter(exp)
	// idle already, the first sweep exports it
	c.Record(FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}, time.Now().Add(-time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx, idleReader{}) }()
	<-exp.entered

	// the agent flushes and closes the exporter once Run returns, a sweep
	// still exporting then would strand its records
	cancel()
	select {
	case <-errCh:
		t.Fatal("Run returned while its sweep was still exporting")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
}

// blockingEnricher holds Enrich for one source address until released, like
// a rib lookup that waits behind a peer purge
type blockingEnricher struct {
	slow    netip.Addr
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (e *blockingEnricher) Enrich(src, dst netip.Addr) (Labels, Labels) {
	if src != e.slow {
		return Labels{ASN: 64501}, Labels{}
	}
	e.once.Do(func() { close(e.entered) })
	<-e.release
	return Labels{ASN: 64500}, Labels{}
}

func TestSlowEnricherDoesNotStallTheCollector(t *testing.T) {
	e := &blockingEnricher{
		slow:    netip.MustParseAddr("::ffff:192.0.2.1"),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(e.release) }) }
	defer release()

	c := New(30*time.Second, e, config.DefaultMaxFlows)
	now := time.Now()
	known := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	c.Record(known, now)

	slow := known
	slow.SrcAddr = e.slow
	recorded := make(chan struct{})
	go func() {
		c.Record(slow, now)
		close(recorded)
	}()
	<-e.entered

	// while the new flow waits for its labels, an existing flow keeps
	// counting and the table stays readable
	done := make(chan struct{})
	go func() {
		c.Record(known, now)
		c.Stats()
		c.Flows()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("recording and reads stalled behind a slow enricher")
	}
	if got := c.Flows()[known.Key()].Packets; got != 2 {
		t.Fatalf("packets of the known flow = %d, want 2", got)
	}

	release()
	<-recorded
	if got := c.Flows()[slow.Key()]; got.Packets != 1 || got.Src.ASN != 64500 {
		t.Fatalf("slow flow = %+v, want one packet with the labels the enricher returned", got)
	}
}

func TestRecordBatchEnrichesFlowsForcedOutWithinTheBatch(t *testing.T) {
	e := &blockingEnricher{slow: netip.MustParseAddr("::ffff:192.0.2.1")}
	c := New(30*time.Second, e, 1)
	t0 := time.Now()

	a := FlowEvent{
		Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	b := a
	b.SrcPort = 2000
	c.Record(a, t0)

	// b forces a out of a table of one, then a comes back as a new flow in
	// the same batch and still needs its labels
	c.RecordBatch([]FlowEvent{b, a}, []time.Time{t0.Add(time.Millisecond), t0.Add(2 * time.Millisecond)})

	flows := c.Flows()
	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(flows))
	}
	if got, ok := flows[a.Key()]; !ok || got.Packets != 1 || got.Src.ASN != 64501 {
		t.Fatalf("flow a = %+v (present %v), want it back with one packet and its labels", got, ok)
	}
	if got := c.Stats().ForcedEvictions; got != 2 {
		t.Fatalf("forced evictions = %d, want 2", got)
	}
}

func TestEvictSkipsFullyExportedFlow(t *testing.T) {
	exp := &mockFlowExporter{}
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetFlowExporter(exp)
	c.SetActiveTimeout(10 * time.Second)

	t0 := time.Now()
	ev := FlowEvent{
		Proto: 17, SrcPort: 5000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetSampleRate(10, 0)
	now := time.Now()

	ev := FlowEvent{
		Tstamp: 1_000,
		Proto:  6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
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
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetFlowExporter(exp)
	c.SetSampleRate(100, 0)

	t0 := time.Now()
	ev := FlowEvent{
		Proto: 17, SrcPort: 5000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     60,
	}
	c.Record(ev, t0)
	c.Evict(t0.Add(time.Minute))

	if got := len(exp.flows); got != 1 {
		t.Fatalf("exported flows = %d, want 1", got)
	}
	rec := exp.flows[0]
	if rec.Packets != 1 || rec.EstPackets != 100 || rec.Octets != 60 {
		t.Fatalf("record = %+v, want 1 sampled packet of 60 octets standing for 100 packets", rec)
	}
	if got := rec.SamplingProbability(); got != 0.01 {
		t.Fatalf("sampling probability = %v, want 0.01", got)
	}
}

func TestAdaptiveSamplingAppliesRateOnDrops(t *testing.T) {
	ev := FlowEvent{
		Ifindex: 1, Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	mr := &sustainedReader{event: encodeWireEvent(ev), drops: 5}

	c := New(100*time.Millisecond, nil, config.DefaultMaxFlows)
	c.SetSampleRate(10, 0)
	var applied atomic.Uint32
	c.SetRateController(10, 40, func(n uint32) error {
		applied.Store(n)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx, mr) }()

	// the first tick sees 5 drops and doubles the rate, later ticks see no
	// new drops and leave it alone until the quiet streak relaxes it
	deadline := time.Now().Add(2 * time.Second)
	for applied.Load() != 20 {
		if time.Now().After(deadline) {
			t.Fatalf("applied rate = %d, want 20", applied.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := c.SampleRate(); got != 20 {
		t.Fatalf("collector rate = %d, want 20", got)
	}

	cancel()
	<-errCh
}

// rollupCounters returns a snapshot of the per label counters
func rollupCounters(c *Collector) map[RollupKey]RollupCounters {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := make(map[RollupKey]RollupCounters, len(c.rollups))
	for k, r := range c.rollups {
		snap[k] = r.RollupCounters
	}
	return snap
}

func TestRollupsOutliveTheirFlows(t *testing.T) {
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	t0 := time.Now()
	ev := FlowEvent{
		Ifindex: 3, Proto: 17, SrcPort: 5000, DstPort: 53,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     60,
	}
	key := RollupKey{Ifindex: 3, Proto: 17}
	c.Record(ev, t0)

	// the tuple stays in the scrape for RollupRetention eviction timeouts
	// after its last packet
	c.Evict(t0.Add(RollupRetention*30*time.Second - time.Second))
	if len(c.Flows()) != 0 {
		t.Fatal("idle flow not evicted")
	}
	if _, ok := rollupCounters(c)[key]; !ok {
		t.Fatal("rollup dropped inside the retention")
	}

	c.Evict(t0.Add(RollupRetention*30*time.Second + time.Second))
	if _, ok := rollupCounters(c)[key]; ok {
		t.Fatal("rollup kept past the retention")
	}
}

func TestScrapeShowsANewRollupAtZeroFirst(t *testing.T) {
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetSampleRate(10, 0)
	t0 := time.Now()
	ev := FlowEvent{
		Ifindex: 3, Proto: 6, SrcPort: 1000, DstPort: 80,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		Segs:    1,
		Len:     100,
	}
	c.Record(ev, t0)

	scrape := func() RollupSample {
		t.Helper()
		samples := c.ScrapeRollups(nil)
		if len(samples) != 1 {
			t.Fatalf("samples = %d, want 1", len(samples))
		}
		return samples[0]
	}

	// the first scrape shows the series at zero, so a rate or increase over
	// the next scrapes counts the packets that created the tuple
	if s := scrape(); s.Key != (RollupKey{Ifindex: 3, Proto: 6}) || s.Packets != 0 || s.EstPackets != 0 || s.Bytes != 0 || s.EstBytes != 0 {
		t.Fatalf("first scrape = %+v, want the tuple at zero", s)
	}
	if s := scrape(); s.Packets != 1 || s.EstPackets != 10 || s.Bytes != 100 || s.EstBytes != 1000 {
		t.Fatalf("second scrape = %+v, want the held packet", s)
	}
	c.Record(ev, t0)
	if s := scrape(); s.Packets != 2 || s.EstPackets != 20 {
		t.Fatalf("third scrape = %+v, want each later packet right away", s)
	}
}

// rateRecorder stands in for the probe, it records every rate written to it
type rateRecorder struct {
	mu      sync.Mutex
	applied []uint32
	fail    error
}

func (r *rateRecorder) apply(n uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.applied = append(r.applied, n)
	return nil
}

func (r *rateRecorder) last() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applied[len(r.applied)-1]
}

func TestManualRateResetsTheController(t *testing.T) {
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetSampleRate(10, 0)
	probe := &rateRecorder{}
	c.SetRateController(10, 1000, probe.apply)

	// an operator sheds load with rfm set sample-rate 200
	if err := c.ApplySampleRate(200); err != nil {
		t.Fatal(err)
	}
	if probe.last() != 200 || c.SampleRate() != 200 {
		t.Fatalf("probe %d collector %d, want both at 200", probe.last(), c.SampleRate())
	}

	// drops while sampling 1 in 200 coarsen from 200, not from the 10 the
	// controller picked last
	c.adapt(5)
	if probe.last() != 400 || c.SampleRate() != 400 {
		t.Fatalf("after drops probe %d collector %d, want both at 400", probe.last(), c.SampleRate())
	}

	// a quiet streak relaxes from there
	for range quietTicks {
		c.adapt(5)
	}
	if probe.last() != 200 || c.SampleRate() != 200 {
		t.Fatalf("after a quiet streak probe %d collector %d, want both at 200", probe.last(), c.SampleRate())
	}
}

func TestManualRateWaitsForAnAdaptiveStep(t *testing.T) {
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetSampleRate(10, 0)
	probe := &rateRecorder{}
	entered := make(chan struct{})
	release := make(chan struct{})
	var first sync.Once
	c.SetRateController(10, 1000, func(n uint32) error {
		first.Do(func() {
			close(entered)
			<-release
		})
		return probe.apply(n)
	})

	// the adaptive step is between its probe write and its history append
	stepped := make(chan struct{})
	go func() {
		c.adapt(5)
		close(stepped)
	}()
	<-entered

	manual := make(chan error, 1)
	go func() { manual <- c.ApplySampleRate(200) }()
	select {
	case err := <-manual:
		close(release)
		t.Fatalf("manual change finished during an adaptive step (err %v), the probe and the scaling can disagree", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	<-stepped
	if err := <-manual; err != nil {
		t.Fatal(err)
	}
	if probe.last() != 200 || c.SampleRate() != 200 {
		t.Fatalf("probe %d collector %d, want both at the manual 200", probe.last(), c.SampleRate())
	}
}

func TestFailedRateChangesKeepTheRateInForce(t *testing.T) {
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetSampleRate(10, 0)
	probe := &rateRecorder{fail: errors.New("map update failed")}
	c.SetRateController(10, 1000, probe.apply)

	if err := c.ApplySampleRate(200); err == nil {
		t.Fatal("ApplySampleRate succeeded with a failing probe")
	}
	c.adapt(5)
	if got := c.SampleRate(); got != 10 {
		t.Fatalf("rate = %d, want the 10 the probe still samples at", got)
	}
	// a refused manual change goes back to the operator, a refused adaptive
	// one has nobody to go back to and is counted
	if got := c.Stats().BPFMapErrors; got != 1 {
		t.Fatalf("bpf map errors = %d, want the one refused adaptive change", got)
	}

	// the controller steps from the rate the probe holds once writes work
	probe.fail = nil
	c.adapt(10)
	if probe.last() != 20 || c.SampleRate() != 20 {
		t.Fatalf("probe %d collector %d, want both at 20", probe.last(), c.SampleRate())
	}
}

// asnPerSource gives every source address an asn of its own, so every flow
// from a new source opens a new label tuple
type asnPerSource struct{}

func (asnPerSource) Enrich(src, dst netip.Addr) (Labels, Labels) {
	b := src.As16()
	return Labels{ASN: 64512 + uint32(b[14])<<8 + uint32(b[15])}, Labels{}
}

func sourceEvent(i int) FlowEvent {
	return FlowEvent{
		Ifindex: 2, Dir: 0, Proto: 17, SrcPort: 5000, DstPort: 53,
		SrcAddr: netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}),
		DstAddr: netip.MustParseAddr("10.0.0.1"),
		Segs:    1,
		Len:     100,
	}
}

func TestRollupsAreCappedAtMaxFlows(t *testing.T) {
	c := New(30*time.Second, asnPerSource{}, 100)
	t0 := time.Now()

	// a scan from many networks, one packet per source
	for i := range 20_000 {
		c.Record(sourceEvent(i), t0)
	}

	rollups := rollupCounters(c)
	overflow := RollupKey{Ifindex: 2, Dir: 0, Proto: 17}
	if len(rollups) > 101 {
		t.Fatalf("rollups = %d, want at most 100 tuples and the overflow tuple", len(rollups))
	}
	var packets uint64
	for _, r := range rollups {
		packets += r.Packets
	}
	if packets != 20_000 {
		t.Fatalf("packets over all tuples = %d, want every one of the 20000", packets)
	}
	folded := c.Stats().FoldedFlows
	if folded == 0 || rollups[overflow].Packets != folded {
		t.Fatalf("folded flows = %d, overflow tuple = %+v, want the folded flows counted under empty labels", folded, rollups[overflow])
	}
}

func TestRollupsAccumulateAcrossFlows(t *testing.T) {
	c := New(30*time.Second, nil, config.DefaultMaxFlows)
	c.SetSampleRate(4, 0)
	t0 := time.Now()

	mk := func(port uint16, proto uint8) FlowEvent {
		return FlowEvent{
			Ifindex: 3, Dir: 0, Proto: proto, SrcPort: port, DstPort: 80,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			Segs:    1,
			Len:     50,
		}
	}
	c.Record(mk(1, 6), t0)
	c.Record(mk(2, 6), t0)
	c.Record(mk(2, 6), t0)
	c.Record(mk(3, 17), t0)

	rollups := rollupCounters(c)
	if len(rollups) != 2 {
		t.Fatalf("rollups = %d, want 2 (tcp and udp)", len(rollups))
	}
	tcp := rollups[RollupKey{Ifindex: 3, Dir: 0, Proto: 6}]
	if tcp.Packets != 3 || tcp.Bytes != 150 || tcp.EstPackets != 12 || tcp.EstBytes != 600 {
		t.Fatalf("tcp rollup = %+v, want 3 packets 150 bytes scaled by 4", tcp)
	}
	udp := rollups[RollupKey{Ifindex: 3, Dir: 0, Proto: 17}]
	if udp.Packets != 1 || udp.EstBytes != 200 {
		t.Fatalf("udp rollup = %+v, want 1 packet 200 estimated bytes", udp)
	}
}
