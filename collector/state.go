package collector

import (
	"encoding/binary"
	"time"
)

// flowState is a live flow and what its earlier records carried, the fields
// an event touches come first and span two cache lines of its slot
type flowState struct {
	// id is the flow's key in the table, a lookup compares it on the lines the event then updates
	id flowID
	// rollup is the slot of the flow's tuple in the rollup table
	rollup rollupRef
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
	// hash is the table hash of id, the index lets go of the flow by it
	hash uint64
	// pad fills the slot to four cache lines, so every slot of a chunk starts on a line
	_ [24]byte
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

// record returns the delta record for the unexported interval, its addresses
// in the 16 byte form the id keeps
func (s *flowState) record(reason uint8) ExportedFlow {
	ne := binary.NativeEndian
	return ExportedFlow{
		SrcAddr:    [16]byte(s.id.addrs[:16]),
		DstAddr:    [16]byte(s.id.addrs[16:]),
		Start:      s.first,
		End:        s.last,
		Packets:    s.entry.Packets - s.sent.packets,
		Octets:     s.entry.IPBytes - s.sent.ipBytes,
		EstPackets: s.entry.EstPackets - s.sent.estPackets,
		Ifindex:    ne.Uint32(s.id.ifindex[:]),
		SrcPort:    ne.Uint16(s.id.ports[:]),
		DstPort:    ne.Uint16(s.id.ports[2:]),
		Dir:        s.id.dir,
		Proto:      s.id.proto,
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
// fields an event touches come first and fit in the first cache line of its slot
type rollupState struct {
	Counts
	lastSeen time.Duration
	// shown is set while the last scrape showed every count of the tuple,
	// only then may it be dropped without losing counts nobody saw
	shown bool
	// exposed is set once a scrape showed the tuple, at zero the first time
	exposed bool
	// links holds the place of the tuple in the idle list while flows is 0
	links rollupLinks
	// flows counts the live flows that count under the tuple
	flows int
	key   RollupKey
	// id tells this life of the tuple apart from any other
	id uint64
}

// add accounts the counts of one event at t of a live flow under the tuple
func (r *rollupState) add(d Counts, t time.Duration) {
	r.Counts.add(d)
	r.lastSeen = max(r.lastSeen, t)
	r.shown = false
}
