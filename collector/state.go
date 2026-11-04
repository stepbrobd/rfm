package collector

import (
	"container/list"
	"time"
)

// flowState is a live flow and what its earlier records carried, the fields
// an event touches come first and span two cache lines of its slot
type flowState struct {
	rollup *rollupState
	// first and last are the min and max event time since the last record, events arrive out of order, 0 before the first
	first, last time.Duration
	// queued is the event time the flow last moved to the back of the lru
	queued time.Duration
	entry  FlowEntry

	// links holds the place of the flow in the lru and in the fifo of pending active timeout exports
	links [2]flowLinks
	// intervalStart is when the not yet exported interval began, the flow's
	// creation or the sweep that marked it, the active timeout runs from it
	intervalStart time.Duration
	// sent holds the counters earlier records carried, the ones a record
	// needs and no more
	sent struct {
		packets, ipBytes, estPackets uint64
	}
	key FlowKey
	// pad fills the slot to four cache lines, so every slot of a chunk starts on a line
	_ [8]byte
}

// seen extends the flow and its unexported interval to an event at t
func (s *flowState) seen(t time.Duration) {
	s.entry.FirstSeen = min(s.entry.FirstSeen, t)
	s.entry.LastSeen = max(s.entry.LastSeen, t)
	if s.first == 0 || t < s.first {
		s.first = t
	}
	s.last = max(s.last, t)
}

// record returns the delta record for the unexported interval
func (s *flowState) record(reason uint8) ExportedFlow {
	return ExportedFlow{
		SrcAddr:    s.key.SrcAddr.As16(),
		DstAddr:    s.key.DstAddr.As16(),
		Start:      s.first,
		End:        s.last,
		Packets:    s.entry.Packets - s.sent.packets,
		Octets:     s.entry.IPBytes - s.sent.ipBytes,
		EstPackets: s.entry.EstPackets - s.sent.estPackets,
		Ifindex:    s.key.Ifindex,
		SrcPort:    s.key.SrcPort,
		DstPort:    s.key.DstPort,
		Dir:        s.key.Dir,
		Proto:      s.key.Proto,
		EndReason:  reason,
	}
}

// pending reports whether the flow saw packets since its last record
func (s *flowState) pending() bool {
	return s.entry.Packets != s.sent.packets
}

// mark records that everything up to now went out in a record
func (s *flowState) mark(now time.Duration) {
	s.sent.packets = s.entry.Packets
	s.sent.ipBytes = s.entry.IPBytes
	s.sent.estPackets = s.entry.EstPackets
	s.intervalStart = now
	s.first, s.last = 0, 0
}

// rollupState is one label tuple with the counters a scrape exposes, the
// fields an event touches come first and span two cache lines
type rollupState struct {
	Counts
	// live sums the counts of the live flows under the tuple
	live     Counts
	lastSeen time.Duration
	// shown is set while the last scrape showed every count of the tuple,
	// only then may it be dropped without losing counts nobody saw
	shown bool
	// exposed is set once a scrape showed the tuple, at zero the first time
	exposed bool
	key     RollupKey
	// id tells this life of the tuple apart from any other
	id uint64
	// flows counts the live flows that count under the tuple
	flows int
	// idle is the position in the collector's idle list while flows is 0
	idle *list.Element
}

// add accounts the counts of one event at t of a live flow under the tuple
func (r *rollupState) add(d Counts, t time.Duration) {
	r.Counts.add(d)
	r.live.add(d)
	r.lastSeen = max(r.lastSeen, t)
	r.shown = false
}
