package collector

import (
	"container/list"
	"time"
)

// flowState is one live flow with its position in the lru list
// the interval fields track what was already exported, so every record
// carries a delta and a flow that exported everything produces no record
type flowState struct {
	key   FlowKey
	entry FlowEntry
	elem  *list.Element

	// active is the position in the fifo of pending active timeout exports
	active *list.Element
	// intervalStart is the start of the not yet exported interval
	intervalStart time.Time
	// sentPackets and sentBytes were exported by earlier records
	sentPackets uint64
	sentBytes   uint64
}

// record returns the delta record for the unexported interval
func (s *flowState) record(reason uint8) ExportedFlow {
	return ExportedFlow{
		Key: s.key,
		Entry: FlowEntry{
			FirstSeen: s.intervalStart,
			LastSeen:  s.entry.LastSeen,
			Packets:   s.entry.Packets - s.sentPackets,
			Bytes:     s.entry.Bytes - s.sentBytes,
		},
		EndReason: reason,
	}
}

// pending reports whether the flow saw packets since its last record
func (s *flowState) pending() bool {
	return s.entry.Packets != s.sentPackets
}

// mark records that everything up to now went out in a record
func (s *flowState) mark(now time.Time) {
	s.sentPackets = s.entry.Packets
	s.sentBytes = s.entry.Bytes
	s.intervalStart = now
}
