package collector

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"ysun.co/rfm/config"
)

func handoffEvent(i int, t time.Duration) FlowEvent {
	return FlowEvent{
		Tstamp:  t,
		Ifindex: 1,
		Proto:   17,
		SrcAddr: netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}),
		DstAddr: netip.MustParseAddr("10.1.0.1"),
		SrcPort: 4000,
		DstPort: 53,
		Segs:    1,
		Len:     100,
	}
}

func TestHandoffRecordsEveryBatchInTheOrderHanded(t *testing.T) {
	c := New(time.Hour, nil, config.DefaultMaxFlows)
	h := c.startHandoff()
	// more batches than stages, every event of one flow a nanosecond after the one before
	const batches = 5 * handoffStages
	batch := make([]sample, 0, readBatch)
	now := time.Hour
	for range batches {
		for range readBatch {
			ev := handoffEvent(0, now)
			batch = append(batch, sample{})
			batch[len(batch)-1].from(&ev)
			now++
		}
		batch = h.hand(batch)
		if len(batch) != 0 || cap(batch) < readBatch {
			t.Fatalf("hand returned a batch of %d records and room for %d, want an empty one with room for %d", len(batch), cap(batch), readBatch)
		}
	}
	h.stop()

	flows := c.Flows()
	if len(flows) != 1 {
		t.Fatalf("%d flows, want 1", len(flows))
	}
	for _, e := range flows {
		if want := uint64(batches * readBatch); e.Packets != want {
			t.Errorf("packets = %d, want %d", e.Packets, want)
		}
		if e.FirstSeen != time.Hour || e.LastSeen != now-1 {
			t.Errorf("first and last seen = %v and %v, want %v and %v", e.FirstSeen, e.LastSeen, time.Hour, now-1)
		}
	}
}

func TestRunHandsOffAndRecordsEveryEvent(t *testing.T) {
	const flows = 1000
	events := make([][]byte, flows)
	for i := range events {
		events[i] = encodeWireEvent(handoffEvent(i, bootNow()))
	}
	c := New(time.Hour, nil, config.DefaultMaxFlows)
	// any load hands off once the first window ends
	c.handoffAt = 0
	ctx, cancel := context.WithCancel(context.Background())
	// a slow reader runs for about three windows
	rd := &pacedReader{cycleReader: cycleReader{events: events, n: 300 * readBatch, cancel: cancel}, every: readBatch, pause: time.Millisecond}
	if err := c.Run(ctx, rd); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	if c.handoffs == 0 {
		t.Fatal("the run never started a recorder")
	}
	var packets uint64
	for _, e := range c.Flows() {
		packets += e.Packets
	}
	if packets != uint64(rd.n) {
		t.Errorf("recorded %d packets, want %d", packets, rd.n)
	}
}

// pacedReader is a cycleReader that pauses after every so many events
type pacedReader struct {
	cycleReader
	every int
	pause time.Duration
}

func (r *pacedReader) ReadRawEvent() ([]byte, error) {
	if r.i > 0 && r.i%r.every == 0 && r.i < r.n {
		time.Sleep(r.pause)
	}
	return r.cycleReader.ReadRawEvent()
}

func TestLoadMeterSharesTheBusyTimeOfTheWindow(t *testing.T) {
	var m loadMeter
	t0 := time.Unix(0, 0)
	if due, _ := m.due(t0, nil); due {
		t.Fatal("the first call opened a window and reported it due")
	}
	m.busy = loadWindow / 4
	if due, _ := m.due(t0.Add(loadWindow/2), nil); due {
		t.Fatal("a window reported due before its length")
	}
	h := &handoff{busy: loadWindow / 2}
	due, share := m.due(t0.Add(loadWindow), h)
	if !due || share != 0.75 {
		t.Fatalf("due = %v share = %v, want true and 0.75", due, share)
	}
	if m.busy != 0 || h.busy != 0 {
		t.Errorf("busy = %v and %v after the window, want both 0", m.busy, h.busy)
	}
}
