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
	flows map[flowID]*flowState
	// lru orders flows by their last event, oldest first, approximate across cpus
	lru *list.List
	// activeQueue orders live flows by the start of their unexported interval, oldest first
	activeQueue *list.List
	// rollups are the label tuples of the flow series, rollupLocked caps the labeled ones
	rollups   map[RollupKey]*rollupState
	rollupIDs uint64
	// idleRollups lists the tuples without live flows, longest idle first
	idleRollups *list.List
	timeout     time.Duration
	active      time.Duration
	enricher    Enricher
	exporter    FlowExporter
	maxFlows    int
	// rates lists the sample rates by the boot time they took effect, oldest first
	rates []rateChange

	// rateMu orders rate changes, the probe's rate is the last in rates, taken before mu
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

// New creates a collector that evicts flows idle for timeout and holds at most maxFlows flows, enricher may be nil
func New(timeout time.Duration, enricher Enricher, maxFlows int) *Collector {
	return &Collector{
		flows:       make(map[flowID]*flowState),
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

// rateHistory bounds rates, an event is recorded long before its rate is 64 changes old
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

// ApplySampleRate installs rate in the probe and for scaling, the adaptive controller continues from it
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

// adapt feeds the drops to the controller once per tick, a rate the probe refuses counts as a bpf map error
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

// SetActiveTimeout makes the sweep export a flow's unexported interval once it is d old, 0 disables it, it must be called before Run
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
	batch := make([]sample, len(evs))
	for i := range evs {
		batch[i].from(&evs[i])
	}
	c.record(batch, evs)
}

// record records batch like RecordBatch, evs holds the events batch came from when the caller had them
func (c *Collector) record(batch []sample, evs []FlowEvent) {
	var expired []ExportedFlow
	var unresolved []int

	c.mu.Lock()
	for i := range batch {
		var ok bool
		if expired, ok = c.recordLocked(&batch[i], eventAt(evs, i), nil, expired); !ok {
			unresolved = append(unresolved, i)
		}
	}
	exp := c.exporter
	c.mu.Unlock()

	if len(unresolved) > 0 {
		pairs := make([]addrPair, len(unresolved))
		for j, i := range unresolved {
			key := newKey(&batch[i], eventAt(evs, i))
			pairs[j] = addrPair{key.SrcAddr, key.DstAddr}
		}
		labels := c.enrich(pairs)

		c.mu.Lock()
		for _, i := range unresolved {
			expired, _ = c.recordLocked(&batch[i], eventAt(evs, i), labels, expired)
		}
		exp = c.exporter
		c.mu.Unlock()
	}

	c.exportFlows(exp, expired)
}

// eventAt returns the event at i of evs, nil when the batch came without its events
func eventAt(evs []FlowEvent, i int) *FlowEvent {
	if evs == nil {
		return nil
	}
	return &evs[i]
}

// newKey returns the key a new flow of s takes, the one of its event when there is one
func newKey(s *sample, ev *FlowEvent) FlowKey {
	if ev != nil {
		return ev.Key()
	}
	return s.id.key()
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

// recordLocked records s and appends the record of a flow it evicts to expired, ok is false when its new flow has no labels yet
func (c *Collector) recordLocked(s *sample, ev *FlowEvent, labels map[addrPair]labelPair, expired []ExportedFlow) (_ []ExportedFlow, ok bool) {
	now := s.tstamp
	packets := uint64(s.segs)
	bytes := uint64(s.len)
	ipBytes := bytes - packets*uint64(s.l2Len)
	rate := uint64(c.sampleRateAtLocked(now))
	d := Counts{Packets: packets, Bytes: bytes, EstPackets: packets * rate, EstBytes: bytes * rate}

	if state, found := c.flows[s.id]; found {
		state.entry.Packets += d.Packets
		state.entry.Bytes += d.Bytes
		state.entry.IPBytes += ipBytes
		state.entry.EstPackets += d.EstPackets
		state.entry.EstBytes += d.EstBytes
		state.seen(now)
		state.rollup.add(d, now)
		c.lru.MoveToBack(state.elem)
		return expired, true
	}

	key := newKey(s, ev)
	var lp labelPair
	if c.enricher != nil {
		var resolved bool
		if lp, resolved = labels[addrPair{key.SrcAddr, key.DstAddr}]; !resolved {
			return expired, false
		}
	}
	src, dst := lp.src, lp.dst

	if len(c.flows) >= c.maxFlows {
		if ended, evicted := c.evictOldestLocked(FlowEndReasonLackOfResources); evicted {
			expired = append(expired, ended)
		}
	}

	rollup := c.rollupLocked(RollupKey{Ifindex: key.Ifindex, Dir: key.Dir, Proto: key.Proto, Src: src, Dst: dst})
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
	c.flows[s.id] = state
	return expired, true
}

// rollupLocked returns the tuple of a new flow, at the cap an idle shown tuple makes room or the flow folds
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
	delete(c.flows, state.key.id())
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
	for _, state := range c.flows {
		snap[state.key] = state.entry
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
	for _, state := range c.flows {
		switch {
		case len(top) < n:
			top = append(top, Flow{state.key, state.entry})
			if len(top) == n {
				for i := n/2 - 1; i >= 0; i-- {
					down(i)
				}
			}
		case ahead(&state.entry, &top[0].FlowEntry):
			top[0] = Flow{state.key, state.entry}
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

// ScrapeRollups appends every tuple to buf, a tuple's first scrape shows its counters at zero
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
	c.flows = make(map[flowID]*flowState)
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

// sweepPeriod splits the active timeout into the fewest parts no longer than half the eviction timeout
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

	batch := make([]sample, 0, readBatch)
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

		batch = c.appendSample(batch[:0], raw)

		// a past deadline drains the rings without blocking
		rd.SetDeadline(time.Now())
		for len(batch) < readBatch {
			raw, err := rd.ReadRawEvent()
			if err != nil {
				break
			}
			batch = c.appendSample(batch, raw)
		}

		if len(batch) > 0 {
			c.record(batch, nil)
		}
	}
}

// appendSample decodes raw onto batch in place, a record that fails to decode is counted and skipped
func (c *Collector) appendSample(batch []sample, raw []byte) []sample {
	batch = append(batch, sample{})
	if err := batch[len(batch)-1].decode(raw); err != nil {
		log.Error("decode flow event", "err", err, "raw_len", len(raw))
		c.ringBufErrs.Add(1)
		return batch[:len(batch)-1]
	}
	return batch
}
