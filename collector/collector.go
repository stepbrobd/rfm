package collector

import (
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
	mu sync.RWMutex
	// flows holds the live flows, its lru is approximate across cpus
	flows flowTable
	// hash is the table hash of a flow id, keyed when the collector is made and fixed from then on
	hash func(*flowID) uint64
	// created counts every flow added to flows, a flush leaves it as it is
	created uint64
	// lruSlack is how much event time passes before an event moves its flow to the back of the lru again
	lruSlack time.Duration
	// live is the reader of a running Run, a scrape reads the ring drops from it
	live Reader
	// rollups holds the label tuples of the flow series, rollupLocked caps the labeled ones
	rollups  rollupTable
	timeout  time.Duration
	active   time.Duration
	enricher Enricher
	exporter FlowExporter
	maxFlows int
	// handoffAt is the busy share of a window from which the run loop hands its batches to a recorder goroutine
	handoffAt float64
	// handoffs counts the recorders the run loop started, only the loop writes it
	handoffs int
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
		flows:     newFlowTable(),
		hash:      newFlowHash().sum,
		rollups:   newRollupTable(),
		timeout:   timeout,
		lruSlack:  timeout / lruSlackParts,
		enricher:  enricher,
		maxFlows:  maxFlows,
		handoffAt: handoffLoad,
		rates:     []rateChange{{rate: 1}},
	}
}

// lruSlackParts splits the eviction timeout into the slack of the lru order, a sweep misses an idle flow by at most one part
const lruSlackParts = 32

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
	c.record(batch, evs, &recordBuf{})
}

// recordBuf holds what recording a batch needs besides its events, Run keeps one across batches so a batch allocates nothing once the buffers have grown
type recordBuf struct {
	// expired holds the records of the flows the batch evicts
	expired []ExportedFlow
	// unresolved holds the positions of the events whose new flows wait for labels, pairs their addresses
	unresolved []int
	pairs      []addrPair
	labels     map[addrPair]labelPair
}

// record records batch like RecordBatch, evs holds the events batch came from when the caller had them
func (c *Collector) record(batch []sample, evs []FlowEvent, buf *recordBuf) {
	buf.unresolved = buf.unresolved[:0]

	// a loop of its own hashes the ids before the lock, so no lookup under the lock waits on a hash
	for i := range batch {
		batch[i].hash = c.hash(&batch[i].id)
	}

	c.mu.Lock()
	// a run of events of one flow, as the ring of a bulk transfer holds, looks the flow up once, the hashes tell most events of other flows apart
	var last flowRef
	for i := range batch {
		s := &batch[i]
		if last == 0 || s.hash != batch[i-1].hash || !s.id.equal(&batch[i-1].id) {
			var found bool
			if last, found = c.flows.get(s.hash, &s.id); !found {
				var ok bool
				if buf.expired, last, ok = c.addLocked(s, eventAt(evs, i), nil, buf.expired); !ok {
					buf.unresolved = append(buf.unresolved, i)
				}
				continue
			}
		}
		c.hitLocked(last, s)
	}
	exp := c.exporter
	c.mu.Unlock()

	if len(buf.unresolved) > 0 {
		buf.pairs = buf.pairs[:0]
		for _, i := range buf.unresolved {
			key := newKey(&batch[i], eventAt(evs, i))
			buf.pairs = append(buf.pairs, addrPair{key.SrcAddr, key.DstAddr})
		}
		if buf.labels == nil {
			buf.labels = make(map[addrPair]labelPair, len(buf.pairs))
		}
		c.enrich(buf.pairs, buf.labels)

		c.mu.Lock()
		// an earlier event of the batch can have added the flow
		for _, i := range buf.unresolved {
			s := &batch[i]
			if r, found := c.flows.get(s.hash, &s.id); found {
				c.hitLocked(r, s)
			} else {
				buf.expired, _, _ = c.addLocked(s, eventAt(evs, i), buf.labels, buf.expired)
			}
		}
		exp = c.exporter
		c.mu.Unlock()
	}

	c.exportFlows(exp, buf.expired)
	buf.expired = buf.expired[:0]
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

// enrich looks up the labels of pairs into labels, which it empties first, it must be called without mu held
func (c *Collector) enrich(pairs []addrPair, labels map[addrPair]labelPair) {
	clear(labels)
	for _, p := range pairs {
		if _, ok := labels[p]; !ok {
			src, dst := c.enricher.Enrich(p.src, p.dst)
			labels[p] = labelPair{src, dst}
		}
	}
}

// addLocked adds the flow of s, which the table does not hold, and appends the record of a flow it evicts to expired, it returns the slot of the new flow, ok is false when the flow has no labels yet
func (c *Collector) addLocked(s *sample, ev *FlowEvent, labels map[addrPair]labelPair, expired []ExportedFlow) (_ []ExportedFlow, _ flowRef, ok bool) {
	now := s.tstamp
	d, ipBytes := c.countsLocked(s)

	// the key's addresses serve only the labels, and its form only an event that named one
	var key FlowKey
	if c.enricher != nil || ev != nil {
		key = newKey(s, ev)
	}
	var lp labelPair
	if c.enricher != nil {
		var resolved bool
		if lp, resolved = labels[addrPair{key.SrcAddr, key.DstAddr}]; !resolved {
			return expired, 0, false
		}
	}
	src, dst := lp.src, lp.dst

	if c.flows.len() >= c.maxFlows {
		if ended, evicted := c.evictOldestLocked(FlowEndReasonLackOfResources); evicted {
			expired = append(expired, ended)
		}
	}

	rollup := c.rollupLocked(RollupKey{Ifindex: s.id.ifIndex(), Dir: s.id.dir, Proto: s.id.proto, Src: src, Dst: dst})
	c.attachLocked(rollup)
	c.rollups.at(rollup).add(d, now)

	c.created++
	r := c.flows.add(&flowState{
		id:   s.id,
		hash: s.hash,
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
		queued:        now,
	})
	// an event of RecordBatch can name an address in a form the id does not keep, the listings show the form it named
	if ev != nil && key != s.id.key() {
		c.flows.keepKey(r, key)
	}
	return expired, r, true
}

// countsLocked returns the counts s adds at the sample rate in force at its time, and the ip bytes of its packets
func (c *Collector) countsLocked(s *sample) (Counts, uint64) {
	packets := uint64(s.segs)
	bytes := uint64(s.len)
	rate := uint64(c.sampleRateAtLocked(s.tstamp))
	return Counts{Packets: packets, Bytes: bytes, EstPackets: packets * rate, EstBytes: bytes * rate}, bytes - packets*uint64(s.l2Len)
}

// hitLocked adds the counts of s to the flow in slot r, which moves to the back of the lru at most once per lruSlack
func (c *Collector) hitLocked(r flowRef, s *sample) {
	now := s.tstamp
	d, ipBytes := c.countsLocked(s)
	state := c.flows.at(r)
	state.entry.Packets += d.Packets
	state.entry.Bytes += d.Bytes
	state.entry.IPBytes += ipBytes
	state.entry.EstPackets += d.EstPackets
	state.entry.EstBytes += d.EstBytes
	state.seen(now)
	c.rollups.at(state.rollup).add(d, now)
	if now-state.queued >= c.lruSlack {
		state.queued = now
		c.flows.moveToBack(lruList, r)
	}
}

// rollupLocked returns the slot of the tuple of a new flow, at the cap an idle shown tuple makes room or the flow folds
func (c *Collector) rollupLocked(rk RollupKey) rollupRef {
	if r, ok := c.rollups.get(rk); ok {
		return r
	}
	labeled := rk.Src != (Labels{}) || rk.Dst != (Labels{})
	if labeled && c.rollups.len() >= c.maxFlows {
		front := c.rollups.front()
		if front != 0 && c.rollups.at(front).shown {
			c.rollups.drop(front)
		} else {
			c.folded.Add(1)
			rk = RollupKey{Ifindex: rk.Ifindex, Dir: rk.Dir, Proto: rk.Proto}
			if r, ok := c.rollups.get(rk); ok {
				return r
			}
		}
	}
	return c.rollups.add(rk)
}

// attachLocked counts a new live flow under the tuple in slot r, which leaves the idle list if it had none
// it must be called with mu held
func (c *Collector) attachLocked(r rollupRef) {
	t := c.rollups.at(r)
	if t.flows == 0 {
		c.rollups.unlink(r)
	}
	t.flows++
}

// detachLocked takes a live flow off the tuple in slot r, a tuple without
// live flows becomes a candidate for retention and for making room
// it must be called with mu held
func (c *Collector) detachLocked(r rollupRef) {
	t := c.rollups.at(r)
	t.flows--
	if t.flows == 0 {
		c.rollups.pushBack(r)
	}
}

// removeLocked drops the flow in slot r from the table, its slot is cleared
// it must be called with mu held
func (c *Collector) removeLocked(r flowRef) {
	c.detachLocked(c.flows.at(r).rollup)
	c.flows.remove(r)
}

// evictOldestLocked removes the flow with the oldest LastSeen
// it must be called with mu held
func (c *Collector) evictOldestLocked(reason uint8) (ExportedFlow, bool) {
	r := c.flows.front(lruList)
	if r == 0 {
		return ExportedFlow{}, false
	}
	var ended ExportedFlow
	oldest := c.flows.at(r)
	pending := oldest.pending()
	if pending {
		ended = oldest.record(reason)
	}
	c.removeLocked(r)
	c.forced.Add(1)
	return ended, pending
}

// Evict sweeps the table once at now, a CLOCK_BOOTTIME reading
func (c *Collector) Evict(now time.Duration) {
	c.sweep(now, 0)
}

// sweepChunk bounds the flows one hold of mu sweeps, the run loop records between the holds of a sweep with many flows to end or report
const sweepChunk = 4096

// sweep is Evict repeated every period, an interval record goes out at the sweep nearest its active timeout
func (c *Collector) sweep(now, period time.Duration) {
	cutoff := now - c.timeout
	// half a period of slack keeps a record from slipping a period when its tick comes early
	due := c.active - period/2
	var expired []ExportedFlow
	idle, active := true, c.active > 0
	for idle || active {
		c.mu.Lock()
		if idle {
			if expired, idle = c.sweepIdleLocked(cutoff, expired); !idle {
				c.dropStaleTuplesLocked(now)
			}
		} else {
			expired, active = c.sweepActiveLocked(now, due, expired)
		}
		exp := c.exporter
		c.mu.Unlock()

		c.exportFlows(exp, expired)
		expired = expired[:0]
	}
}

// sweepIdleLocked ends up to sweepChunk flows idle since before cutoff and reports whether more are left, a record is built only for an exporter
// it must be called with mu held
func (c *Collector) sweepIdleLocked(cutoff time.Duration, expired []ExportedFlow) (_ []ExportedFlow, more bool) {
	for range sweepChunk {
		r := c.flows.front(lruList)
		if r == 0 {
			return expired, false
		}
		oldest := c.flows.at(r)
		if oldest.entry.LastSeen >= cutoff {
			return expired, false
		}
		if c.exporter != nil && oldest.pending() {
			expired = append(expired, oldest.record(FlowEndReasonIdleTimeout))
		}
		c.removeLocked(r)
	}
	return expired, true
}

// dropStaleTuplesLocked drops the shown tuples idle since before the retention, in the order they lost their last flow, a dropped one leaves the scrape
// it must be called with mu held
func (c *Collector) dropStaleTuplesLocked(now time.Duration) {
	stale := now - RollupRetention*c.timeout
	for r := c.rollups.front(); r != 0; r = c.rollups.front() {
		if t := c.rollups.at(r); t.lastSeen >= stale || !t.shown {
			break
		}
		c.rollups.drop(r)
	}
}

// sweepActiveLocked starts a new interval for up to sweepChunk flows whose interval is due at now and reports whether more are left, a record of the old interval is built only for an exporter
// it must be called with mu held
func (c *Collector) sweepActiveLocked(now, due time.Duration, expired []ExportedFlow) (_ []ExportedFlow, more bool) {
	for range sweepChunk {
		r := c.flows.front(activeList)
		if r == 0 {
			return expired, false
		}
		state := c.flows.at(r)
		if now-state.intervalStart < due {
			return expired, false
		}
		if c.exporter != nil && state.pending() {
			expired = append(expired, state.record(FlowEndReasonActiveTimeout))
		}
		state.mark(now)
		c.flows.moveToBack(activeList, r)
	}
	return expired, true
}

// Flows returns a snapshot of the current flow table
func (c *Collector) Flows() map[FlowKey]FlowEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := make(map[FlowKey]FlowEntry, c.flows.len())
	for r, state := range c.flows.all() {
		snap[c.flows.key(r)] = state.entry
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
	top := make([]Flow, 0, min(n, c.flows.len()))
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
	for r, state := range c.flows.all() {
		switch {
		case len(top) < n:
			top = append(top, Flow{c.flows.key(r), state.entry})
			if len(top) == n {
				for i := n/2 - 1; i >= 0; i-- {
					down(i)
				}
			}
		case ahead(&state.entry, &top[0].FlowEntry):
			top[0] = Flow{c.flows.key(r), state.entry}
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
}

// ScrapeRollups appends every tuple to buf, a tuple's first scrape shows its counters at zero
func (c *Collector) ScrapeRollups(buf []RollupSample) []RollupSample {
	c.mu.Lock()
	defer c.mu.Unlock()

	for r := range c.rollups.all() {
		s := RollupSample{Key: r.key, ID: r.id}
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
	activeFlows := uint64(c.flows.len())
	created := c.created
	live := c.live
	c.mu.RUnlock()

	// the sweep polls the drops once a period, a scrape reads them now
	if live != nil {
		if n, err := live.DroppedEvents(); err != nil {
			c.bpfMapErrs.Add(1)
		} else {
			c.noteDrops(n)
		}
	}

	return Stats{
		ActiveFlows:     activeFlows,
		CreatedFlows:    created,
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
	exp = c.exporter
	if c.flows.len() > 0 {
		// a record is built only for an exporter
		if exp != nil {
			expired = make([]ExportedFlow, 0, c.flows.len())
		}
		for _, state := range c.flows.all() {
			if exp != nil && state.pending() {
				expired = append(expired, state.record(reason))
			}
			c.detachLocked(state.rollup)
		}
	}
	c.flows = newFlowTable()
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
	c.noteDrops(dropped)
	c.adapt(dropped)
}

// noteDrops raises the drop count to n, the sweep's poll and a scrape both read the counter of the programs
func (c *Collector) noteDrops(n uint64) {
	for {
		old := c.dropped.Load()
		if n <= old || c.dropped.CompareAndSwap(old, n) {
			return
		}
	}
}

// readBatch caps how many events are recorded per lock acquisition, the last
// record of a batch may carry it past the cap, and how many records the reader
// takes from one ring in a turn
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

	c.mu.Lock()
	period := sweepPeriod(c.timeout, c.active)
	c.live = rd
	c.mu.Unlock()
	defer func() {
		if n, err := rd.DroppedEvents(); err != nil {
			c.bpfMapErrs.Add(1)
		} else {
			c.noteDrops(n)
		}
		c.mu.Lock()
		c.live = nil
		c.mu.Unlock()
	}()
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

	// room for a handed off batch and the last record that crosses its limit, so no append grows it
	batch := make([]sample, 0, handoffBatch+maxRecordEvents)
	// a table at its cap evicts a flow for each new one, one buffer holds the records and the labels of batch after batch
	var buf recordBuf
	// h records the batches while the loop alone cannot keep up, nil while the loop records inline
	var h *handoff
	defer func() {
		if h != nil {
			h.stop()
		}
	}()
	var load loadMeter
	// first is when the batch in hand got its first record, zero between batches
	var first time.Time
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		now := time.Now()
		if !first.IsZero() {
			load.busy += now.Sub(first)
			first = time.Time{}
		}
		if due, share := load.due(now, h); due {
			switch {
			case h == nil && share >= c.handoffAt:
				log.Debug("hand batches to a recorder", "busy", share)
				h = c.startHandoff()
				c.handoffs++
			case h != nil && share < inlineLoad:
				log.Debug("record batches inline", "busy", share)
				h.stop()
				h = nil
			}
		}
		rd.SetDeadline(now.Add(readDeadline))
		raw, err := rd.ReadRawEvent()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			c.ringBufErrs.Add(1)
			return fmt.Errorf("read event: %w", err)
		}
		first = time.Now()
		batch = c.appendSamples(batch[:0], raw)

		// a past deadline drains the rings without blocking
		rd.SetDeadline(first)
		limit := readBatch
		if h != nil {
			limit = handoffBatch
		}
		for len(batch) < limit {
			raw, err := rd.ReadRawEvent()
			if err != nil {
				break
			}
			batch = c.appendSamples(batch, raw)
		}

		switch {
		case len(batch) == 0:
		case h != nil:
			batch = h.hand(batch)
		default:
			c.record(batch, nil, &buf)
		}
	}
}

// appendSamples decodes the events of the record raw onto batch in place, a
// record of a length that is not a positive multiple of the event size counts
// as one error and is skipped, an event that fails to decode counts as one and
// is skipped while the others of its record are kept
func (c *Collector) appendSamples(batch []sample, raw []byte) []sample {
	// a load without a stage writes every event as a record of its own
	if len(raw) == wireFlowEventSize {
		batch = append(batch, sample{})
		if err := batch[len(batch)-1].decode(raw); err != nil {
			log.Error("decode flow event", "err", err, "event", 0, "events", 1)
			c.ringBufErrs.Add(1)
			return batch[:len(batch)-1]
		}
		return batch
	}
	n, err := recordEvents(raw)
	if err != nil {
		log.Error("decode flow event record", "err", err)
		c.ringBufErrs.Add(1)
		return batch
	}
	for i := range n {
		batch = append(batch, sample{})
		if err := batch[len(batch)-1].decode(recordEvent(raw, i)); err != nil {
			log.Error("decode flow event", "err", err, "event", i, "events", n)
			c.ringBufErrs.Add(1)
			batch = batch[:len(batch)-1]
		}
	}
	return batch
}
