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
	rollup *RollupCounters

	// active is the position in the fifo of pending active timeout exports
	active *list.Element
	// intervalStart is the start of the not yet exported interval
	intervalStart time.Time
	// sent holds the counters already exported by earlier records
	sent FlowEntry
}

// record returns the delta record for the unexported interval
func (s *flowState) record(reason uint8) ExportedFlow {
	return ExportedFlow{
		Key: s.key,
		Entry: FlowEntry{
			FirstSeen:  s.intervalStart,
			LastSeen:   s.entry.LastSeen,
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
}

// add accounts one event scaled by the rate that sampled it
func (r *RollupCounters) add(packets, bytes, rate uint64, now time.Time) {
	r.Packets += packets
	r.Bytes += bytes
	r.EstPackets += packets * rate
	r.EstBytes += bytes * rate
	if now.After(r.LastSeen) {
		r.LastSeen = now
	}
}
