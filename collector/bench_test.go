package collector

import (
	"context"
	"fmt"
	"net/netip"
	"os"
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

func BenchmarkRun(b *testing.B) {
	for _, flows := range []int{1000, config.DefaultMaxFlows} {
		b.Run(fmt.Sprintf("flows=%d", flows), func(b *testing.B) {
			events := make([][]byte, flows)
			for i := range events {
				events[i] = encodeWireEvent(FlowEvent{
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
			c := New(time.Hour, nil, config.DefaultMaxFlows)
			ctx, cancel := context.WithCancel(context.Background())
			rd := &cycleReader{events: events, n: b.N, cancel: cancel}
			b.ReportAllocs()
			b.ResetTimer()
			if err := c.Run(ctx, rd); err != context.Canceled {
				b.Fatal(err)
			}
		})
	}
}
