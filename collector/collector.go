package collector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Collector aggregates flow events into an in-memory flow table
type Collector struct {
	mu      sync.RWMutex
	flows   map[FlowKey]*FlowEntry
	timeout time.Duration
	total   uint64
	dropped uint64
}

// New creates a collector that evicts flows older than timeout
func New(timeout time.Duration) *Collector {
	return &Collector{
		flows:   make(map[FlowKey]*FlowEntry),
		timeout: timeout,
	}
}

// Record adds a flow event to the table, creating or updating the entry
func (c *Collector) Record(ev FlowEvent, now time.Time) {
	key := ev.Key()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.total++

	entry, ok := c.flows[key]
	if !ok {
		c.flows[key] = &FlowEntry{
			Packets:  1,
			Bytes:    uint64(ev.Len),
			LastSeen: now,
		}
		return
	}

	entry.Packets++
	entry.Bytes += uint64(ev.Len)
	entry.LastSeen = now
}

// Evict removes flows whose LastSeen is older than the configured timeout
func (c *Collector) Evict(now time.Time) {
	cutoff := now.Add(-c.timeout)

	c.mu.Lock()
	defer c.mu.Unlock()

	for k, v := range c.flows {
		if v.LastSeen.Before(cutoff) {
			delete(c.flows, k)
		}
	}
}

// Flows returns a snapshot of the current flow table
func (c *Collector) Flows() map[FlowKey]FlowEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := make(map[FlowKey]FlowEntry, len(c.flows))
	for k, v := range c.flows {
		snap[k] = *v
	}
	return snap
}

// Stats returns collector-level statistics
func (c *Collector) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return Stats{
		ActiveFlows:   uint64(len(c.flows)),
		TotalEvents:   c.total,
		DroppedEvents: c.dropped,
	}
}

// Run reads events from rd, decodes them, and records them until ctx is done.
// It also runs a background eviction goroutine at timeout/2 intervals.
func (c *Collector) Run(ctx context.Context, rd Reader) error {
	tick := time.NewTicker(c.timeout / 2)
	defer tick.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-tick.C:
				c.Evict(t)
			}
		}
	}()

	for {
		rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
		raw, err := rd.ReadRawEvent()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if dropped, derr := rd.DroppedEvents(); derr == nil {
					c.mu.Lock()
					c.dropped = dropped
					c.mu.Unlock()
				}
				continue
			}
			return fmt.Errorf("read event: %w", err)
		}

		ev, err := DecodeFlowEvent(raw)
		if err != nil {
			continue
		}

		c.Record(ev, time.Now())
	}
}
