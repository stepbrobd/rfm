package collector

import (
	"net/netip"
	"time"
)

// Enricher provides optional metadata for flow addresses.
// Implementations include MMDB (GeoIP) and BMP/RIB lookups.
// nil Enricher means zero-value labels.
type Enricher interface {
	Enrich(src, dst netip.Addr) (srcLabels, dstLabels Labels)
}

// Labels holds enrichment metadata for a single address
type Labels struct {
	ASN  uint32
	City string
}

// FlowEvent represents a single packet observation from the BPF program
type FlowEvent struct {
	Tstamp  uint64 // CLOCK_BOOTTIME nanoseconds
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
	Len     uint32
}

// Key returns the flow key for this event, suitable as a map key
func (e FlowEvent) Key() FlowKey {
	return FlowKey{
		Ifindex: e.Ifindex,
		Dir:     e.Dir,
		Proto:   e.Proto,
		SrcAddr: e.SrcAddr,
		DstAddr: e.DstAddr,
		SrcPort: e.SrcPort,
		DstPort: e.DstPort,
	}
}

// FlowKey identifies a unique flow by its 5-tuple plus interface and direction
type FlowKey struct {
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
}

// FlowEntry holds aggregated counters for a single flow
type FlowEntry struct {
	Packets  uint64
	Bytes    uint64
	LastSeen time.Time
}

// Stats holds collector-level statistics
type Stats struct {
	ActiveFlows     uint64
	DroppedEvents   uint64
	ForcedEvictions uint64
	RingBufErrors   uint64
	BPFMapErrors    uint64
}
