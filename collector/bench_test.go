package collector

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"ysun.co/rfm/config"
)

// cycleReader hands out pre-encoded events of distinct flows in turn and
// cancels the run after n of them, so one benchmark op is one event through
// decode and record
type cycleReader struct {
	events [][]byte
	n, i   int
	cancel context.CancelFunc
}

func (r *cycleReader) ReadRawEvent() ([]byte, error) {
	if r.i >= r.n {
		r.cancel()
		return nil, os.ErrDeadlineExceeded
	}
	ev := r.events[r.i%len(r.events)]
	r.i++
	return ev, nil
}

func (r *cycleReader) SetDeadline(time.Time)          {}
func (r *cycleReader) DroppedEvents() (uint64, error) { return 0, nil }
func (r *cycleReader) Close() error                   { return nil }

// BenchmarkRun records on the run loop's goroutine, so an op is the cost of
// one event, the handoff cases let a recorder take the batches off the loop,
// so an op is the time one event adds to a saturated run
func BenchmarkRun(b *testing.B) {
	for _, handoff := range []bool{false, true} {
		for _, enricher := range []Enricher{nil, asnPerSource{}} {
			// four times the flows the table holds evict its oldest flow on every event
			for _, flows := range []int{1000, config.DefaultMaxFlows, 4 * config.DefaultMaxFlows} {
				if handoff && (enricher != nil || flows != 1000) {
					continue
				}
				benchmarkRun(b, flows, enricher, handoff)
			}
		}
	}
}

// heldFlows is how many flows BenchmarkHeldFlows holds, half its cap so that it evicts none
const heldFlows = 1 << 20

// heldEvents encodes one event of each held flow, once for every round of the benchmark
var heldEvents = sync.OnceValue(func() [][]byte {
	events := make([][]byte, heldFlows)
	for i := range events {
		events[i] = encodeWireEvent(FlowEvent{
			Tstamp:  bootNow(),
			Ifindex: 1,
			Proto:   6,
			SrcAddr: netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}),
			DstAddr: netip.MustParseAddr("192.0.2.1"),
			SrcPort: uint16(1024 + i%60000),
			DstPort: 443,
			Segs:    1,
			Len:     1500,
		})
	}
	return events
})

// BenchmarkHeldFlows reports the heap a held flow takes in a large table and times events of flows it holds
func BenchmarkHeldFlows(b *testing.B) {
	events := heldEvents()
	c := New(time.Hour, nil, 2*heldFlows)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	runEvents(b, c, events, heldFlows)
	runtime.GC()
	runtime.ReadMemStats(&after)
	if n := c.Stats().ActiveFlows; n != heldFlows {
		b.Fatalf("the table holds %d flows, want %d", n, heldFlows)
	}

	b.ReportAllocs()
	b.ResetTimer()
	runEvents(b, c, events, b.N)
	// a timer reset drops the metrics reported before it
	b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc))/heldFlows, "heap-B/flow")
}

// runEvents runs c over n events, taken from events in turn
func runEvents(b *testing.B, c *Collector, events [][]byte, n int) {
	ctx, cancel := context.WithCancel(context.Background())
	if err := c.Run(ctx, &cycleReader{events: events, n: n, cancel: cancel}); err != context.Canceled {
		b.Fatal(err)
	}
}

func benchmarkRun(b *testing.B, flows int, enricher Enricher, handoff bool) {
	name := fmt.Sprintf("flows=%d", flows)
	if enricher != nil {
		name += "/enricher"
	}
	if handoff {
		name += "/handoff"
	}
	b.Run(name, func(b *testing.B) {
		events := make([][]byte, flows)
		for i := range events {
			events[i] = encodeWireEvent(FlowEvent{
				Tstamp:  bootNow(),
				Ifindex: 1,
				Proto:   6,
				SrcAddr: netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}),
				DstAddr: netip.MustParseAddr("10.1.0.1"),
				SrcPort: uint16(1024 + i%60000),
				DstPort: 443,
				Segs:    1,
				Len:     1500,
			})
		}
		c := New(time.Hour, enricher, config.DefaultMaxFlows)
		if !handoff {
			c.handoffAt = 2
		}
		ctx, cancel := context.WithCancel(context.Background())
		rd := &cycleReader{events: events, n: b.N, cancel: cancel}
		b.ReportAllocs()
		b.ResetTimer()
		if err := c.Run(ctx, rd); err != context.Canceled {
			b.Fatal(err)
		}
	})
}
