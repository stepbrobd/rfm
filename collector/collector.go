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
	lru *list.List
	// activeQueue orders live flows by the start of their unexported
	// interval, front first, for the active timeout sweep
	activeQueue *list.List
	// rollups accumulate per label tuple and outlive the flows behind
	// them, an idle tuple is dropped after rollupRetention timeouts
	rollups  map[RollupKey]*RollupCounters
	timeout  time.Duration
	active   time.Duration
	enricher Enricher
	exporter FlowExporter
	maxFlows int
	// rates lists the sample rates in force over boot time, oldest first,
	// so an event is scaled by the rate that sampled it even after the
	// rate changed at runtime
	rates []rateChange

	// controller adapts the rate to ring drops when set, apply writes the
	// new rate into the probe
	controller *rateController
	applyRate  func(uint32) error
	lastDrops  uint64

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
		flows:       make(map[FlowKey]*flowState),
		lru:         list.New(),
		activeQueue: list.New(),
		rollups:     make(map[RollupKey]*RollupCounters),
		timeout:     timeout,
		enricher:    enricher,
		maxFlows:    maxFlows,
		rates:       []rateChange{{rate: 1}},
	}
}

// rollupRetention is how many eviction timeouts a rollup survives without
// traffic before its series disappears from the scrape
const rollupRetention = 10

// rateChange is one sample rate in force from a boot time onwards
type rateChange struct {
	since uint64
	rate  uint32
}

// rateHistory bounds how many rate changes are kept, events are consumed
// within milliseconds so old changes are never consulted again
const rateHistory = 64

// SetSampleRate records that packets sampled from boot time since on are
// 1-in-rate samples, since is CLOCK_BOOTTIME nanoseconds and 0 covers
// everything seen so far
func (c *Collector) SetSampleRate(rate uint32, since uint64) {
	if rate == 0 {
		rate = 1
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if since == 0 {
		c.rates = []rateChange{{rate: rate}}
		return
	}
	c.rates = append(c.rates, rateChange{since: since, rate: rate})
	if len(c.rates) > rateHistory {
		c.rates = c.rates[len(c.rates)-rateHistory:]
	}
}

// SetRateController enables adaptive sampling between base and maxRate
// apply installs a new rate in the probe, the collector records the change
// for scaling once apply succeeded
// it must be called before Run
func (c *Collector) SetRateController(base, maxRate uint32, apply func(uint32) error) {
	c.mu.Lock()
	c.controller = newRateController(base, maxRate)
	c.applyRate = apply
	c.mu.Unlock()
}

// adapt feeds the drop counter to the controller once per tick
func (c *Collector) adapt(drops uint64) {
	c.mu.Lock()
	ctl, apply := c.controller, c.applyRate
	delta := drops - c.lastDrops
	c.lastDrops = drops
	c.mu.Unlock()
	if ctl == nil {
		return
	}

	rate, changed := ctl.step(delta)
	if !changed {
		return
	}
	if err := apply(rate); err != nil {
		log.Error("apply sample rate", "rate", rate, "err", err)
		return
	}
	c.SetSampleRate(rate, bootNow())
	log.Info("sample rate adapted", "rate", rate, "drops", delta)
}

// SetSampleRateNow records a rate change that applies from now on
func (c *Collector) SetSampleRateNow(rate uint32) {
	c.SetSampleRate(rate, bootNow())
}

// SampleRate returns the rate in force now
func (c *Collector) SampleRate() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rates[len(c.rates)-1].rate
}

// sampleRateAtLocked returns the rate in force at boot time tstamp
// it must be called with mu held
func (c *Collector) sampleRateAtLocked(tstamp uint64) uint32 {
	for i := len(c.rates) - 1; i > 0; i-- {
		if c.rates[i].since <= tstamp {
			return c.rates[i].rate
		}
	}
	return c.rates[0].rate
}

// SetActiveTimeout makes every sweep export an interval record for flows
// whose unexported interval is at least d old, 0 disables the sweep
// it must be called before Run
func (c *Collector) SetActiveTimeout(d time.Duration) {
	c.mu.Lock()
	c.active = d
	c.mu.Unlock()
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
	packets := ev.Packets()
	bytes := uint64(ev.Len)
	ipBytes := ev.IPBytes()
	rate := uint64(c.sampleRateAtLocked(ev.Tstamp))

	if state, ok := c.flows[key]; ok {
		state.entry.Packets += packets
		state.entry.Bytes += bytes
		state.entry.IPBytes += ipBytes
		state.entry.EstPackets += packets * rate
		state.entry.EstBytes += bytes * rate
		state.seen(now)
		state.rollup.add(packets, bytes, rate, now)
		c.lru.MoveToBack(state.elem)
		return ExportedFlow{}, false
	}

	var ended ExportedFlow
	var evicted bool
	if c.maxFlows > 0 && len(c.flows) >= c.maxFlows {
		ended, evicted = c.evictOldestLocked(FlowEndReasonLackOfResources)
	}

	// enrichment happens once per flow, the labels then ride along with
	// every event of the flow and with the rollup it lands in
	var src, dst Labels
	if c.enricher != nil {
		src, dst = c.enricher.Enrich(ev.SrcAddr, ev.DstAddr)
	}
	rk := RollupKey{Ifindex: ev.Ifindex, Dir: ev.Dir, Proto: ev.Proto, Src: src, Dst: dst}
	rollup, ok := c.rollups[rk]
	if !ok {
		rollup = &RollupCounters{}
		c.rollups[rk] = rollup
	}
	rollup.add(packets, bytes, rate, now)

	state := &flowState{
		key: key,
		entry: FlowEntry{
			FirstSeen:  now,
			Packets:    packets,
			Bytes:      bytes,
			IPBytes:    ipBytes,
			EstPackets: packets * rate,
			EstBytes:   bytes * rate,
			LastSeen:   now,
			Src:        src,
			Dst:        dst,
		},
		rollup:        rollup,
		intervalStart: now,
		first:         now,
		last:          now,
	}
	state.elem = c.lru.PushBack(state)
	state.active = c.activeQueue.PushBack(state)
	c.flows[key] = state
	return ended, evicted
}

// removeLocked drops a flow from the table and both lists
// it must be called with mu held
func (c *Collector) removeLocked(state *flowState) {
	c.lru.Remove(state.elem)
	c.activeQueue.Remove(state.active)
	delete(c.flows, state.key)
}

// evictOldestLocked removes the flow with the oldest LastSeen
// it must be called with mu held
func (c *Collector) evictOldestLocked(reason uint8) (ExportedFlow, bool) {
	front := c.lru.Front()
	if front == nil {
		return ExportedFlow{}, false
	}
	oldest := front.Value.(*flowState)
	c.removeLocked(oldest)
	c.forced.Add(1)
	if !oldest.pending() {
		return ExportedFlow{}, false
	}
	return oldest.record(reason), true
}

// Evict removes flows whose LastSeen is older than the configured timeout
// and, when an active timeout is set, exports an interval record for every
// flow whose unexported interval is at least that old
func (c *Collector) Evict(now time.Time) {
	cutoff := now.Add(-c.timeout)
	var expired []ExportedFlow

	c.mu.Lock()

	for {
		front := c.lru.Front()
		if front == nil || !front.Value.(*flowState).entry.LastSeen.Before(cutoff) {
			break
		}
		oldest := front.Value.(*flowState)
		c.removeLocked(oldest)
		if oldest.pending() {
			expired = append(expired, oldest.record(FlowEndReasonIdleTimeout))
		}
	}

	if len(c.rollups) > 0 {
		stale := now.Add(-rollupRetention * c.timeout)
		for rk, rollup := range c.rollups {
			if rollup.LastSeen.Before(stale) {
				delete(c.rollups, rk)
			}
		}
	}

	if c.active > 0 {
		for {
			front := c.activeQueue.Front()
			if front == nil {
				break
			}
			state := front.Value.(*flowState)
			if now.Sub(state.intervalStart) < c.active {
				break
			}
			if state.pending() {
				expired = append(expired, state.record(FlowEndReasonActiveTimeout))
			}
			state.mark(now)
			c.activeQueue.MoveToBack(front)
		}
	}

	exp := c.exporter
	c.mu.Unlock()

	c.exportFlows(exp, expired)
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

// Rollups returns a snapshot of the per label counters
func (c *Collector) Rollups() map[RollupKey]RollupCounters {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := make(map[RollupKey]RollupCounters, len(c.rollups))
	for k, r := range c.rollups {
		snap[k] = *r
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
			if state.pending() {
				expired = append(expired, state.record(reason))
			}
		}
	}
	c.flows = make(map[FlowKey]*flowState)
	c.lru.Init()
	c.activeQueue.Init()
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
	c.adapt(dropped)
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
