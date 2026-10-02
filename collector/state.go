package collector

import (
	"container/list"
	"time"
)

// flowState is one live flow with its position in the lru list
// the interval fields track what was already exported, so every record
// carries a delta and a flow that exported everything produces no record
type flowState struct {
	key    FlowKey
	entry  FlowEntry
	elem   *list.Element
	rollup *rollupState

	// active is the position in the fifo of pending active timeout exports
	active *list.Element
	// intervalStart is when the not yet exported interval began, the flow's
	// creation or the sweep that marked it, the active timeout runs from it
	intervalStart time.Time
	// first and last are the earliest and latest event times since the last
	// record, events from different cpus and events sampled before a sweep
	// but consumed after it arrive out of order, so a record spans the
	// events it carries and never ends before it starts
	first, last time.Time
	// sent holds the counters already exported by earlier records
	sent FlowEntry
}

// seen extends the flow and its unexported interval to an event at now
func (s *flowState) seen(now time.Time) {
	if now.Before(s.entry.FirstSeen) {
		s.entry.FirstSeen = now
	}
	if now.After(s.entry.LastSeen) {
		s.entry.LastSeen = now
	}
	if s.first.IsZero() || now.Before(s.first) {
		s.first = now
	}
	if now.After(s.last) {
		s.last = now
	}
}

// record returns the delta record for the unexported interval
func (s *flowState) record(reason uint8) ExportedFlow {
	return ExportedFlow{
		Key: s.key,
		Entry: FlowEntry{
			FirstSeen:  s.first,
			LastSeen:   s.last,
			Packets:    s.entry.Packets - s.sent.Packets,
			Bytes:      s.entry.Bytes - s.sent.Bytes,
			IPBytes:    s.entry.IPBytes - s.sent.IPBytes,
			EstPackets: s.entry.EstPackets - s.sent.EstPackets,
			EstBytes:   s.entry.EstBytes - s.sent.EstBytes,
		},
		EndReason: reason,
	}
}

// pending reports whether the flow saw packets since its last record
func (s *flowState) pending() bool {
	return s.entry.Packets != s.sent.Packets
}

// mark records that everything up to now went out in a record
func (s *flowState) mark(now time.Time) {
	s.sent = s.entry
	s.intervalStart = now
	s.first, s.last = time.Time{}, time.Time{}
}

// rollupState is one label tuple with the counters a scrape exposes
type rollupState struct {
	RollupCounters
	key RollupKey
	// flows counts the live flows that count under the tuple
	flows int
	// idle is the position in the collector's idle list while flows is 0
	idle *list.Element
	// exposed is set once a scrape showed the tuple, at zero the first time
	exposed bool
	// shown is set while the last scrape showed every count of the tuple,
	// only then may it be dropped without losing counts nobody saw
	shown bool
}

// add accounts one event scaled by the rate that sampled it
func (r *rollupState) add(packets, bytes, rate uint64, now time.Time) {
	r.Packets += packets
	r.Bytes += bytes
	r.EstPackets += packets * rate
	r.EstBytes += bytes * rate
	if now.After(r.LastSeen) {
		r.LastSeen = now
	}
	r.shown = false
}
