package collector

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/log"
)

// Collector aggregates flow events into an in-memory flow table
type Collector struct {
	mu          sync.RWMutex
	flows       map[FlowKey]*flowState
	eviction    flowHeap
	timeout     time.Duration
	enricher    Enricher
	exporter    FlowExporter
	maxFlows    int
	dropped     uint64
	forced      uint64
	ringBufErrs uint64
	bpfMapErrs  uint64
	ipfixErrs   uint64
}

// New creates a collector that evicts flows older than timeout
// enricher may be nil
// maxFlows <= 0 means unlimited
func New(timeout time.Duration, enricher Enricher, maxFlows int) *Collector {
	c := &Collector{
		flows:    make(map[FlowKey]*flowState),
		timeout:  timeout,
		enricher: enricher,
		maxFlows: maxFlows,
	}
	heap.Init(&c.eviction)
	return c
}

// Enricher returns the enricher passed to New
func (c *Collector) Enricher() Enricher {
	return c.enricher
}

// SetFlowExporter sets the exporter for completed flows
func (c *Collector) SetFlowExporter(exp FlowExporter) {
	c.mu.Lock()
	c.exporter = exp
	c.mu.Unlock()
}

// Record adds a flow event to the table
// it creates or updates the entry
func (c *Collector) Record(ev FlowEvent, now time.Time) {
	key := ev.Key()
	var expired []ExportedFlow
	var exp FlowExporter

	c.mu.Lock()

	state, ok := c.flows[key]
	if !ok {
		if c.maxFlows > 0 && len(c.flows) >= c.maxFlows {
			if ended, ok := c.evictOldestLocked(FlowEndReasonEndOfFlow); ok {
				expired = append(expired, ended)
			}
		}
		state = &flowState{
			key: key,
			entry: FlowEntry{
				FirstSeen: now,
				Packets:   1,
				Bytes:     uint64(ev.Len),
				LastSeen:  now,
			},
		}
		c.flows[key] = state
		heap.Push(&c.eviction, state)
		exp = c.exporter
		c.mu.Unlock()
		c.exportFlows(exp, expired)
		return
	}

	state.entry.Packets++
	state.entry.Bytes += uint64(ev.Len)
	state.entry.LastSeen = now
	heap.Fix(&c.eviction, state.index)
	exp = c.exporter
	c.mu.Unlock()
	c.exportFlows(exp, expired)
}

// evictOldestLocked removes the flow with the oldest LastSeen
// it must be called with mu held
func (c *Collector) evictOldestLocked(reason uint8) (ExportedFlow, bool) {
	oldest := c.eviction.peek()
	if oldest == nil {
		return ExportedFlow{}, false
	}

	delete(c.flows, oldest.key)
	heap.Pop(&c.eviction)
	c.forced++
	return ExportedFlow{
		Key:       oldest.key,
		Entry:     oldest.entry,
		EndReason: reason,
	}, true
}

// Evict removes flows whose LastSeen is older than the configured timeout
func (c *Collector) Evict(now time.Time) {
	cutoff := now.Add(-c.timeout)
	var expired []ExportedFlow
	var exp FlowExporter

	c.mu.Lock()

	for {
		oldest := c.eviction.peek()
		if oldest == nil || !oldest.entry.LastSeen.Before(cutoff) {
			exp = c.exporter
			c.mu.Unlock()
			c.exportFlows(exp, expired)
			return
		}

		delete(c.flows, oldest.key)
		heap.Pop(&c.eviction)
		expired = append(expired, ExportedFlow{
			Key:       oldest.key,
			Entry:     oldest.entry,
			EndReason: FlowEndReasonIdleTimeout,
		})
	}
}

// Flows returns a snapshot of the current flow table
func (c *Collector) Flows() map[FlowKey]FlowEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := make(map[FlowKey]FlowEntry, len(c.flows))
	for k, state := range c.flows {
		snap[k] = state.entry
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
		IPFIXErrors:     c.ipfixErrs,
	}
}

// Flush exports all remaining flows and clears the flow table
func (c *Collector) Flush(reason uint8) {
	var expired []ExportedFlow
	var exp FlowExporter

	c.mu.Lock()
	if len(c.flows) > 0 {
		expired = make([]ExportedFlow, 0, len(c.flows))
		for _, state := range c.flows {
			expired = append(expired, ExportedFlow{
				Key:       state.key,
				Entry:     state.entry,
				EndReason: reason,
			})
		}
	}
	c.flows = make(map[FlowKey]*flowState)
	c.eviction = nil
	heap.Init(&c.eviction)
	exp = c.exporter
	c.mu.Unlock()

	c.exportFlows(exp, expired)
}

func (c *Collector) exportFlows(exp FlowExporter, flows []ExportedFlow) {
	if exp == nil {
		return
	}
	var failed int
	for _, flow := range flows {
		if err := exp.ExportFlow(flow); err != nil {
			failed++
			if failed == 1 {
				log.Error("export flow", "err", err)
			}
		}
	}
	if failed == 0 {
		return
	}
	if failed > 1 {
		log.Error("export flow batch", "failed", failed, "total", len(flows))
	}
	c.mu.Lock()
	c.ipfixErrs += uint64(failed)
	c.mu.Unlock()
}

func (c *Collector) pollDrops(rd Reader) {
	dropped, err := rd.DroppedEvents()
	c.mu.Lock()
	if err != nil {
		log.Error("poll dropped events", "err", err)
		c.bpfMapErrs++
	} else {
		c.dropped = dropped
	}
	c.mu.Unlock()
}

// Run reads events from rd, decodes them, and records them until ctx is done
// It also runs a background goroutine for eviction and drop counter polling
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
			log.Error("decode flow event", "err", err, "raw_len", len(raw))
			c.mu.Lock()
			c.ringBufErrs++
			c.mu.Unlock()
			continue
		}

		c.Record(ev, eventTime(ev))
	}
}
