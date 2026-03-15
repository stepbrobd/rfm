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
	mu          sync.RWMutex
	flows       map[FlowKey]*FlowEntry
	timeout     time.Duration
	enricher    Enricher
	maxFlows    int
	dropped     uint64
	forced      uint64
	ringBufErrs uint64
	bpfMapErrs  uint64
}

// New creates a collector that evicts flows older than timeout.
// enricher may be nil. maxFlows <= 0 means unlimited.
func New(timeout time.Duration, enricher Enricher, maxFlows int) *Collector {
	return &Collector{
		flows:    make(map[FlowKey]*FlowEntry),
		timeout:  timeout,
		enricher: enricher,
		maxFlows: maxFlows,
	}
}

// Enricher returns the enricher passed to New.
func (c *Collector) Enricher() Enricher {
	return c.enricher
}

// Record adds a flow event to the table, creating or updating the entry
func (c *Collector) Record(ev FlowEvent, now time.Time) {
	key := ev.Key()

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.flows[key]
	if !ok {
		if c.maxFlows > 0 && len(c.flows) >= c.maxFlows {
			c.evictOldest()
		}
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

// evictOldest removes the flow with the oldest LastSeen. Must be called with mu held.
func (c *Collector) evictOldest() {
	var oldestKey FlowKey
	var oldestTime time.Time
	first := true

	for k, v := range c.flows {
		if first || v.LastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.LastSeen
			first = false
		}
	}

	if !first {
		delete(c.flows, oldestKey)
		c.forced++
	}
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
		ActiveFlows:     uint64(len(c.flows)),
		DroppedEvents:   c.dropped,
		ForcedEvictions: c.forced,
		RingBufErrors:   c.ringBufErrs,
		BPFMapErrors:    c.bpfMapErrs,
	}
}

func (c *Collector) pollDrops(rd Reader) {
	dropped, err := rd.DroppedEvents()
	c.mu.Lock()
	if err != nil {
		c.bpfMapErrs++
	} else {
		c.dropped = dropped
	}
	c.mu.Unlock()
}

// Run reads events from rd, decodes them, and records them until ctx is done.
// It also runs a background goroutine for eviction and drop counter polling.
func (c *Collector) Run(ctx context.Context, rd Reader) error {
	if c.timeout <= 0 {
		return fmt.Errorf("eviction timeout must be positive, got %v", c.timeout)
	}

	tick := time.NewTicker(c.timeout / 2)
	defer tick.Stop()

	// derive a child context so the background goroutine exits
	// when Run returns, even on non-context reader errors
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-tick.C:
				c.Evict(t)
				c.pollDrops(rd)
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
		raw, err := rd.ReadRawEvent()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				c.pollDrops(rd)
				continue
			}
			c.mu.Lock()
			c.ringBufErrs++
			c.mu.Unlock()
			return fmt.Errorf("read event: %w", err)
		}

		ev, err := DecodeFlowEvent(raw)
		if err != nil {
			c.mu.Lock()
			c.ringBufErrs++
			c.mu.Unlock()
			continue
		}

		c.Record(ev, eventTime(ev))
	}
}
