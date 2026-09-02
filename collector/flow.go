package collector

import (
	"net/netip"
	"time"
)

// Enricher provides optional metadata for flow addresses
// implementations include MMDB (GeoIP) and BMP/RIB lookups
// a nil Enricher means zero-value labels
type Enricher interface {
	Enrich(src, dst netip.Addr) (srcLabels, dstLabels Labels)
}

// Labels holds enrichment metadata for a single address
type Labels struct {
	ASN  uint32
	City string
}

// FlowEvent represents a single sampled skb observation from the BPF program
// one skb can stand for several wire packets after GRO or before GSO, so Segs
// carries the wire packet count and Len the wire byte count of the whole skb
// a Segs of 0 comes from a probe without segment accounting and means 1
type FlowEvent struct {
	Tstamp  uint64 // CLOCK_BOOTTIME nanoseconds
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
	Segs    uint16
	Len     uint32
}

// Packets returns the number of wire packets the event stands for
func (e FlowEvent) Packets() uint64 {
	if e.Segs == 0 {
		return 1
	}
	return uint64(e.Segs)
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
	FirstSeen time.Time
	Packets   uint64
	Bytes     uint64
	LastSeen  time.Time
}

// Stats holds collector-level statistics
type Stats struct {
	ActiveFlows     uint64
	DroppedEvents   uint64
	ForcedEvictions uint64
	RingBufErrors   uint64
	BPFMapErrors    uint64
	IPFIXErrors     uint64
}
