package collector

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/log"
)

// Collector aggregates flow events into an in-memory flow table
type Collector struct {
	mu    sync.RWMutex
	flows map[FlowKey]*flowState
	// lru orders flows by last seen time with the oldest at the front
	// a flow moves to the back on every packet, so idle eviction and forced
	// eviction both pop the front in constant time
	// events from different cpus can arrive slightly out of order, which
	// makes the order approximate by a few microseconds, an expired flow can
	// then survive one extra sweep behind a fresher one
	lru      *list.List
	timeout  time.Duration
	enricher Enricher
	exporter FlowExporter
	maxFlows int

	dropped     atomic.Uint64
	forced      atomic.Uint64
	ringBufErrs atomic.Uint64
	bpfMapErrs  atomic.Uint64
	ipfixErrs   atomic.Uint64
}

// New creates a collector that evicts flows older than timeout
// enricher may be nil
// maxFlows <= 0 means unlimited
func New(timeout time.Duration, enricher Enricher, maxFlows int) *Collector {
	return &Collector{
		flows:    make(map[FlowKey]*flowState),
		lru:      list.New(),
		timeout:  timeout,
		enricher: enricher,
		maxFlows: maxFlows,
	}
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
	c.RecordBatch([]FlowEvent{ev}, []time.Time{now})
}

// RecordBatch records several events under one lock acquisition
// at[i] is the observation time of evs[i]
func (c *Collector) RecordBatch(evs []FlowEvent, at []time.Time) {
	var expired []ExportedFlow

	c.mu.Lock()
	for i, ev := range evs {
		if ended, ok := c.recordLocked(ev, at[i]); ok {
			expired = append(expired, ended)
		}
	}
	exp := c.exporter
	c.mu.Unlock()

	c.exportFlows(exp, expired)
}

// recordLocked creates or updates the flow for ev
// it returns the flow forced out to make room, if any
// it must be called with mu held
func (c *Collector) recordLocked(ev FlowEvent, now time.Time) (ExportedFlow, bool) {
	key := ev.Key()

	if state, ok := c.flows[key]; ok {
		state.entry.Packets += ev.Packets()
		state.entry.Bytes += uint64(ev.Len)
		state.entry.LastSeen = now
		c.lru.MoveToBack(state.elem)
		return ExportedFlow{}, false
	}

	var ended ExportedFlow
	var evicted bool
	if c.maxFlows > 0 && len(c.flows) >= c.maxFlows {
		ended, evicted = c.evictOldestLocked(FlowEndReasonLackOfResources)
	}

	state := &flowState{
		key: key,
		entry: FlowEntry{
			FirstSeen: now,
			Packets:   ev.Packets(),
			Bytes:     uint64(ev.Len),
			LastSeen:  now,
		},
	}
	state.elem = c.lru.PushBack(state)
	c.flows[key] = state
	return ended, evicted
}

// evictOldestLocked removes the flow with the oldest LastSeen
// it must be called with mu held
func (c *Collector) evictOldestLocked(reason uint8) (ExportedFlow, bool) {
	front := c.lru.Front()
	if front == nil {
		return ExportedFlow{}, false
	}
	oldest := c.lru.Remove(front).(*flowState)

	delete(c.flows, oldest.key)
	c.forced.Add(1)
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
		front := c.lru.Front()
		if front == nil || !front.Value.(*flowState).entry.LastSeen.Before(cutoff) {
			exp = c.exporter
			c.mu.Unlock()
			c.exportFlows(exp, expired)
			return
		}
		oldest := c.lru.Remove(front).(*flowState)

		delete(c.flows, oldest.key)
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
	activeFlows := uint64(len(c.flows))
	c.mu.RUnlock()

	return Stats{
		ActiveFlows:     activeFlows,
		DroppedEvents:   c.dropped.Load(),
		ForcedEvictions: c.forced.Load(),
		RingBufErrors:   c.ringBufErrs.Load(),
		BPFMapErrors:    c.bpfMapErrs.Load(),
		IPFIXErrors:     c.ipfixErrs.Load(),
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
	c.lru.Init()
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
	c.ipfixErrs.Add(uint64(failed))
}

func (c *Collector) pollDrops(rd Reader) {
	dropped, err := rd.DroppedEvents()
	if err != nil {
		log.Error("poll dropped events", "err", err)
		c.bpfMapErrs.Add(1)
		return
	}
	c.dropped.Store(dropped)
}

// readBatch caps how many ring buffer records are recorded per lock acquisition
const readBatch = 64

// readDeadline bounds a blocking read so the loop notices a cancelled context
const readDeadline = 100 * time.Millisecond

// Run reads events from rd, decodes them, and records them until ctx is done
// It also runs a background goroutine for eviction and drop counter polling
// the drop counter is polled from that goroutine only, once per tick, so the
// read loop never spends a map lookup on an idle deadline
// after a blocking read the loop drains whatever the ring already holds with
// an expired deadline, so a burst is recorded under one lock instead of one
// lock per event
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
				refreshBootOffset()
				c.Evict(t)
				c.pollDrops(rd)
			}
		}
	}()

	events := make([]FlowEvent, 0, readBatch)
	times := make([]time.Time, 0, readBatch)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rd.SetDeadline(time.Now().Add(readDeadline))
		raw, err := rd.ReadRawEvent()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			c.ringBufErrs.Add(1)
			return fmt.Errorf("read event: %w", err)
		}

		events, times = events[:0], times[:0]
		events, times = c.appendEvent(events, times, raw)

		// a deadline in the past turns the read into a poll, an empty ring
		// comes back as a deadline error and a real error surfaces again
		// on the next blocking read
		rd.SetDeadline(time.Now())
		for len(events) < readBatch {
			raw, err := rd.ReadRawEvent()
			if err != nil {
				break
			}
			events, times = c.appendEvent(events, times, raw)
		}

		if len(events) > 0 {
			c.RecordBatch(events, times)
		}
	}
}

// appendEvent decodes raw and appends it with its observation time
// a record that fails to decode is counted and skipped
func (c *Collector) appendEvent(events []FlowEvent, times []time.Time, raw []byte) ([]FlowEvent, []time.Time) {
	ev, err := DecodeFlowEvent(raw)
	if err != nil {
		log.Error("decode flow event", "err", err, "raw_len", len(raw))
		c.ringBufErrs.Add(1)
		return events, times
	}
	return append(events, ev), append(times, eventTime(ev))
}
