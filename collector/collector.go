package collector

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
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
	// them, an idle tuple is dropped after RollupRetention eviction timeouts
	// a new tuple with enrichment labels needs room, fewer than maxFlows
	// tuples of any kind or an idle one a scrape has shown in full to take
	// the place of, otherwise its flow counts under the tuple of its
	// interface, direction and protocol with empty labels, which never needs
	// room of its own, so only tuples with empty labels grow it past maxFlows
	rollups   map[RollupKey]*rollupState
	rollupIDs uint64
	// idleRollups lists the tuples no live flow counts under, longest idle
	// at the front, the ones retention or a new tuple may drop
	idleRollups *list.List
	timeout     time.Duration
	active      time.Duration
	enricher    Enricher
	exporter    FlowExporter
	maxFlows    int
	// rates lists the sample rates in force over boot time, oldest first,
	// so an event is scaled by the rate that sampled it even after the
	// rate changed at runtime
	rates []rateChange

	// rateMu serializes every sample rate change, manual or adaptive, so a
	// change writes the probe and appends to rates in one step and the rate
	// the probe samples at is always the last one in rates
	// it guards the fields below and is taken before mu
	rateMu sync.Mutex
	// applyRate writes a new rate into the probe, controller adapts the rate to ring drops when set
	applyRate  func(uint32) error
	controller *rateController
	lastDrops  uint64

	dropped     atomic.Uint64
	forced      atomic.Uint64
	folded      atomic.Uint64
	ringBufErrs atomic.Uint64
	bpfMapErrs  atomic.Uint64
}

// New creates a collector that evicts flows older than timeout
// enricher may be nil
// maxFlows caps the flow table and the room for new label tuples with
// enrichment labels, Run refuses a cap below 1
func New(timeout time.Duration, enricher Enricher, maxFlows int) *Collector {
	return &Collector{
		flows:       make(map[FlowKey]*flowState),
		lru:         list.New(),
		activeQueue: list.New(),
		rollups:     make(map[RollupKey]*rollupState),
		idleRollups: list.New(),
		timeout:     timeout,
		enricher:    enricher,
		maxFlows:    maxFlows,
		rates:       []rateChange{{rate: 1}},
	}
}

// RollupRetention is how many eviction timeouts a shown idle tuple stays in the scrape
const RollupRetention = 10

// rateChange is one sample rate in force from a boot time onwards
type rateChange struct {
	since time.Duration
	rate  uint32
}

// rateHistory bounds how many rate changes are kept, events are consumed
// within milliseconds so old changes are never consulted again
const rateHistory = 64

// SetRateApplier puts rate in force and makes apply how a later rate reaches the probe, it must be called before Run
func (c *Collector) SetRateApplier(rate uint32, apply func(uint32) error) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	c.applyRate = apply
	c.mu.Lock()
	c.rates = []rateChange{{rate: rate}}
	c.mu.Unlock()
}

// SetRateController enables adaptive sampling between base and maxRate, it must be called before Run
func (c *Collector) SetRateController(base, maxRate uint32) {
	c.rateMu.Lock()
	c.controller = newRateController(base, maxRate)
	c.rateMu.Unlock()
}

// addRate records that the events sampled from boot time since on are 1 in rate samples
func (c *Collector) addRate(rate uint32, since time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rates = append(c.rates, rateChange{since: since, rate: rate})
	if len(c.rates) > rateHistory {
		c.rates = c.rates[len(c.rates)-rateHistory:]
	}
}

// ApplySampleRate installs rate in the probe and records it for scaling, the
// adaptive controller, if any, continues from rate instead of the rate it
// picked last
func (c *Collector) ApplySampleRate(rate uint32) error {
	if rate == 0 {
		return errors.New("sample rate must be at least 1")
	}

	c.rateMu.Lock()
	defer c.rateMu.Unlock()

	if c.applyRate == nil {
		return errors.New("no probe to apply the sample rate to")
	}
	if err := c.applyRate(rate); err != nil {
		return err
	}
	c.addRate(rate, bootNow())
	if c.controller != nil {
		c.controller.reset(rate)
	}
	return nil
}

// adapt feeds the drop counter to the controller once per tick
// a rate the probe refuses counts as a bpf map error, adapt has no caller to
// return it to
func (c *Collector) adapt(drops uint64) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()

	delta := drops - c.lastDrops
	c.lastDrops = drops
	if c.controller == nil {
		return
	}

	prev := c.controller.rate
	rate, changed := c.controller.step(delta)
	if !changed {
		return
	}
	if err := c.applyRate(rate); err != nil {
		// the probe still samples at the previous rate, so the controller
		// steps from there next time
		c.controller.reset(prev)
		c.bpfMapErrs.Add(1)
		log.Error("apply sample rate", "rate", rate, "err", err)
		return
	}
	c.addRate(rate, bootNow())
	log.Info("sample rate adapted", "rate", rate, "drops", delta)
}

// SampleRate returns the rate in force now
func (c *Collector) SampleRate() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rates[len(c.rates)-1].rate
}

// sampleRateAtLocked returns the rate in force at boot time t
func (c *Collector) sampleRateAtLocked(t time.Duration) uint32 {
	for i := len(c.rates) - 1; i > 0; i-- {
		if c.rates[i].since <= t {
			return c.rates[i].rate
		}
	}
	return c.rates[0].rate
}

// SetActiveTimeout makes every sweep export an interval record for flows
// whose unexported interval is at least d old, a sweep of Run already when it
// is less than half a period short, 0 disables the sweep
// it must be called before Run
func (c *Collector) SetActiveTimeout(d time.Duration) {
	c.mu.Lock()
	c.active = d
	c.mu.Unlock()
}

// SetFlowExporter sets the exporter for completed flows
func (c *Collector) SetFlowExporter(exp FlowExporter) {
	c.mu.Lock()
	c.exporter = exp
	c.mu.Unlock()
}

// Record records ev
func (c *Collector) Record(ev FlowEvent) {
	c.RecordBatch([]FlowEvent{ev})
}

// RecordBatch records evs, the labels of new flows are looked up between two passes under the lock
func (c *Collector) RecordBatch(evs []FlowEvent) {
	var expired []ExportedFlow
	var unresolved []int

	c.mu.Lock()
	for i, ev := range evs {
		ended, evicted, ok := c.recordLocked(ev, nil)
		if !ok {
			unresolved = append(unresolved, i)
		} else if evicted {
			expired = append(expired, ended)
		}
	}
	exp := c.exporter
	c.mu.Unlock()

	if len(unresolved) > 0 {
		pairs := make([]addrPair, len(unresolved))
		for j, i := range unresolved {
			pairs[j] = addrPair{evs[i].SrcAddr, evs[i].DstAddr}
		}
		labels := c.enrich(pairs)

		c.mu.Lock()
		for _, i := range unresolved {
			if ended, evicted, _ := c.recordLocked(evs[i], labels); evicted {
				expired = append(expired, ended)
			}
		}
		exp = c.exporter
		c.mu.Unlock()
	}

	c.exportFlows(exp, expired)
}

// addrPair is what one Enrich call looks up
type addrPair struct {
	src, dst netip.Addr
}

// labelPair is what one Enrich call returns
type labelPair struct {
	src, dst Labels
}

// enrich looks up the labels of pairs, it must be called without mu held
func (c *Collector) enrich(pairs []addrPair) map[addrPair]labelPair {
	labels := make(map[addrPair]labelPair, len(pairs))
	for _, p := range pairs {
		if _, ok := labels[p]; !ok {
			src, dst := c.enricher.Enrich(p.src, p.dst)
			labels[p] = labelPair{src, dst}
		}
	}
	return labels
}

// recordLocked records ev, ok is false when its new flow has no labels yet
func (c *Collector) recordLocked(ev FlowEvent, labels map[addrPair]labelPair) (ended ExportedFlow, evicted, ok bool) {
	now := ev.Tstamp
	key := ev.Key()
	packets := ev.Packets()
	bytes := uint64(ev.Len)
	ipBytes := ev.IPBytes()
	rate := uint64(c.sampleRateAtLocked(ev.Tstamp))
	d := Counts{Packets: packets, Bytes: bytes, EstPackets: packets * rate, EstBytes: bytes * rate}

	if state, found := c.flows[key]; found {
		state.entry.Packets += d.Packets
		state.entry.Bytes += d.Bytes
		state.entry.IPBytes += ipBytes
		state.entry.EstPackets += d.EstPackets
		state.entry.EstBytes += d.EstBytes
		state.seen(now)
		state.rollup.add(d, now)
		c.lru.MoveToBack(state.elem)
		return ExportedFlow{}, false, true
	}

	var lp labelPair
	if c.enricher != nil {
		var resolved bool
		if lp, resolved = labels[addrPair{ev.SrcAddr, ev.DstAddr}]; !resolved {
			return ExportedFlow{}, false, false
		}
	}
	src, dst := lp.src, lp.dst

	if len(c.flows) >= c.maxFlows {
		ended, evicted = c.evictOldestLocked(FlowEndReasonLackOfResources)
	}

	rollup := c.rollupLocked(RollupKey{Ifindex: ev.Ifindex, Dir: ev.Dir, Proto: ev.Proto, Src: src, Dst: dst})
	c.attachLocked(rollup)
	rollup.add(d, now)

	state := &flowState{
		key: key,
		entry: FlowEntry{
			FirstSeen:  now,
			Packets:    d.Packets,
			Bytes:      d.Bytes,
			IPBytes:    ipBytes,
			EstPackets: d.EstPackets,
			EstBytes:   d.EstBytes,
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
	return ended, evicted, true
}

// rollupLocked returns the tuple a new flow with key rk counts under
// when the labeled tuples fill the cap, the longest idle one makes room if a
// scrape has shown all it counted, its series then ends at that value and
// a sum over all series stays exact, otherwise the flow folds into the tuple
// with empty labels, whose counts a scrape shows like any other
// it must be called with mu held
func (c *Collector) rollupLocked(rk RollupKey) *rollupState {
	if r, ok := c.rollups[rk]; ok {
		return r
	}
	labeled := rk.Src != (Labels{}) || rk.Dst != (Labels{})
	if labeled && len(c.rollups) >= c.maxFlows {
		front := c.idleRollups.Front()
		if front != nil && front.Value.(*rollupState).shown {
			c.dropRollupLocked(front.Value.(*rollupState))
		} else {
			c.folded.Add(1)
			rk = RollupKey{Ifindex: rk.Ifindex, Dir: rk.Dir, Proto: rk.Proto}
			if r, ok := c.rollups[rk]; ok {
				return r
			}
		}
	}
	c.rollupIDs++
	r := &rollupState{key: rk, id: c.rollupIDs}
	c.rollups[rk] = r
	return r
}

// attachLocked counts a new live flow under r
// it must be called with mu held
func (c *Collector) attachLocked(r *rollupState) {
	if r.idle != nil {
		c.idleRollups.Remove(r.idle)
		r.idle = nil
	}
	r.flows++
}

// detachLocked takes a live flow with entry e off r, a tuple without live
// flows becomes a candidate for retention and for making room
// it must be called with mu held
func (c *Collector) detachLocked(r *rollupState, e FlowEntry) {
	r.live.sub(e.counts())
	r.flows--
	if r.flows == 0 {
		r.idle = c.idleRollups.PushBack(r)
	}
}

// dropRollupLocked removes an idle tuple, its series leaves the scrape
// it must be called with mu held
func (c *Collector) dropRollupLocked(r *rollupState) {
	c.idleRollups.Remove(r.idle)
	r.idle = nil
	delete(c.rollups, r.key)
}

// removeLocked drops a flow from the table and both lists
// it must be called with mu held
func (c *Collector) removeLocked(state *flowState) {
	c.lru.Remove(state.elem)
	c.activeQueue.Remove(state.active)
	delete(c.flows, state.key)
	c.detachLocked(state.rollup, state.entry)
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

// Evict sweeps the table once at now, a CLOCK_BOOTTIME reading
func (c *Collector) Evict(now time.Duration) {
	c.sweep(now, 0)
}

// sweep is Evict repeated every period, an interval record goes out at the sweep nearest its active timeout
func (c *Collector) sweep(now, period time.Duration) {
	cutoff := now - c.timeout
	var expired []ExportedFlow

	c.mu.Lock()

	for {
		front := c.lru.Front()
		if front == nil || front.Value.(*flowState).entry.LastSeen >= cutoff {
			break
		}
		oldest := front.Value.(*flowState)
		c.removeLocked(oldest)
		if oldest.pending() {
			expired = append(expired, oldest.record(FlowEndReasonIdleTimeout))
		}
	}

	// idle tuples are in the order they lost their last flow
	stale := now - RollupRetention*c.timeout
	for front := c.idleRollups.Front(); front != nil; front = c.idleRollups.Front() {
		r := front.Value.(*rollupState)
		if r.lastSeen >= stale || !r.shown {
			break
		}
		c.dropRollupLocked(r)
	}

	if c.active > 0 {
		// half a period of slack keeps a record from slipping a period when its tick comes early
		due := c.active - period/2
		for {
			front := c.activeQueue.Front()
			if front == nil {
				break
			}
			state := front.Value.(*flowState)
			if now-state.intervalStart < due {
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

// Flow is one live flow
type Flow struct {
	Key FlowKey
	FlowEntry
}

// TopFlows returns the n flows with the most estimated packets or bytes, busiest first and the older of a tie first
func (c *Collector) TopFlows(n int, byPackets bool) []Flow {
	if n < 1 {
		return nil
	}
	ahead := func(a, b *FlowEntry) bool {
		if byPackets {
			if a.EstPackets != b.EstPackets {
				return a.EstPackets > b.EstPackets
			}
		} else if a.EstBytes != b.EstBytes {
			return a.EstBytes > b.EstBytes
		}
		return a.FirstSeen < b.FirstSeen
	}

	c.mu.RLock()
	// once full, top is a heap with the flow furthest behind at its root
	top := make([]Flow, 0, min(n, len(c.flows)))
	down := func(i int) {
		for {
			last := i
			for _, child := range [2]int{2*i + 1, 2*i + 2} {
				if child < len(top) && ahead(&top[last].FlowEntry, &top[child].FlowEntry) {
					last = child
				}
			}
			if last == i {
				return
			}
			top[i], top[last] = top[last], top[i]
			i = last
		}
	}
	for k, state := range c.flows {
		switch {
		case len(top) < n:
			top = append(top, Flow{k, state.entry})
			if len(top) == n {
				for i := n/2 - 1; i >= 0; i-- {
					down(i)
				}
			}
		case ahead(&state.entry, &top[0].FlowEntry):
			top[0] = Flow{k, state.entry}
			down(0)
		}
	}
	c.mu.RUnlock()

	sort.Slice(top, func(i, j int) bool { return ahead(&top[i].FlowEntry, &top[j].FlowEntry) })
	return top
}

// RollupSample is one rollup tuple as a scrape shows it
type RollupSample struct {
	Key RollupKey
	// ID tells this life of the tuple apart from any other, a tuple that is
	// dropped and seen again comes back under a new ID
	ID uint64
	// Counts are the monotonic counters of the tuple
	Counts
	// Flows is the number of live flows under the tuple, Live sums their
	// counts, the gauges of a tuple without live flows are not exported
	Flows int
	Live  Counts
}

// ScrapeRollups appends every rollup tuple to buf for a scrape and returns it
// a tuple no scrape has shown yet is shown with its counters at zero and its
// counts appear from the next scrape on, so every series starts at zero and
// rate() and increase() count the packets that created it instead of taking
// its first value for history
// the lock is held for the copy only, a scrape never walks the flow table
func (c *Collector) ScrapeRollups(buf []RollupSample) []RollupSample {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, r := range c.rollups {
		s := RollupSample{Key: k, ID: r.id, Flows: r.flows, Live: r.live}
		if r.exposed {
			s.Counts = r.Counts
			r.shown = true
		}
		r.exposed = true
		buf = append(buf, s)
	}
	return buf
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
		FoldedFlows:     c.folded.Load(),
		RingBufErrors:   c.ringBufErrs.Load(),
		BPFMapErrors:    c.bpfMapErrs.Load(),
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
			c.detachLocked(state.rollup, state.entry)
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
	if failed > 1 {
		log.Error("export flow batch", "failed", failed, "total", len(flows))
	}
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

// sweepPeriod is how often Run sweeps, every half eviction timeout, or, as
// the sweep also sends the interval records, the active timeout split into
// the fewest equal parts no longer than that, so the records of a flow fall
// on a sweep one active timeout apart
func sweepPeriod(timeout, active time.Duration) time.Duration {
	period := timeout / 2
	if active <= 0 {
		return period
	}
	parts := (active + period - 1) / period
	return active / parts
}

// Run records the events of rd until ctx is done, a ticker sweeps and polls the drops
func (c *Collector) Run(ctx context.Context, rd Reader) error {
	if c.timeout <= 0 {
		return fmt.Errorf("eviction timeout must be positive, got %v", c.timeout)
	}
	if c.maxFlows < 1 {
		return fmt.Errorf("max flows must be positive, got %d", c.maxFlows)
	}

	c.mu.RLock()
	period := sweepPeriod(c.timeout, c.active)
	c.mu.RUnlock()
	tick := time.NewTicker(period)
	defer tick.Stop()

	// the sweep goroutine ends before Run returns
	var sweeps sync.WaitGroup
	defer sweeps.Wait()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sweeps.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				c.sweep(bootNow(), period)
				c.pollDrops(rd)
			}
		}
	})

	events := make([]FlowEvent, 0, readBatch)
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

		events = c.appendEvent(events[:0], raw)

		// a past deadline drains the rings without blocking
		rd.SetDeadline(time.Now())
		for len(events) < readBatch {
			raw, err := rd.ReadRawEvent()
			if err != nil {
				break
			}
			events = c.appendEvent(events, raw)
		}

		if len(events) > 0 {
			c.RecordBatch(events)
		}
	}
}

// appendEvent decodes raw onto events, a record that fails to decode is counted and skipped
func (c *Collector) appendEvent(events []FlowEvent, raw []byte) []FlowEvent {
	ev, err := DecodeFlowEvent(raw)
	if err != nil {
		log.Error("decode flow event", "err", err, "raw_len", len(raw))
		c.ringBufErrs.Add(1)
		return events
	}
	return append(events, ev)
}
