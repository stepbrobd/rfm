//go:build linux

package collector

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type ringReader struct {
	rd    *ringbuf.Reader
	drops *ebpf.Map
}

// NewReader wraps a ring buffer map and a per-CPU drop counter map
func NewReader(events, drops *ebpf.Map) (Reader, error) {
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	return &ringReader{rd: rd, drops: drops}, nil
}

func (r *ringReader) ReadRawEvent() ([]byte, error) {
	rec, err := r.rd.Read()
	if err != nil {
		return nil, err
	}
	return rec.RawSample, nil
}

func (r *ringReader) SetDeadline(t time.Time) {
	r.rd.SetDeadline(t)
}

func (r *ringReader) DroppedEvents() (uint64, error) {
	var key uint32
	var vals []uint64
	if err := r.drops.Lookup(key, &vals); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total, nil
}

func (r *ringReader) Close() error {
	return r.rd.Close()
}
