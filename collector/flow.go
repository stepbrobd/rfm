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
// Packets and Bytes count what was sampled, EstPackets and EstBytes scale
// every event by the sample rate in force when it was sampled, so they stay
// unbiased estimates of the wire totals across runtime rate changes
type FlowEntry struct {
	FirstSeen  time.Time
	Packets    uint64
	Bytes      uint64
	EstPackets uint64
	EstBytes   uint64
	LastSeen   time.Time
	// Src and Dst are the enrichment labels resolved when the flow was
	// created, they stay fixed for the life of the flow
	Src Labels
	Dst Labels
}

// RollupKey is the label tuple the Prometheus flow series are keyed by
// it carries no ports, so its cardinality is bounded by interfaces, protocols
// and the enrichment labels seen
type RollupKey struct {
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	Src     Labels
	Dst     Labels
}

// RollupCounters accumulate every event recorded under one RollupKey
// unlike FlowEntry they never reset when flows are evicted, so they export
// as monotonic counters that rate() and increase() can consume
type RollupCounters struct {
	Packets    uint64
	Bytes      uint64
	EstPackets uint64
	EstBytes   uint64
	LastSeen   time.Time
}

// SamplingProbability is the share of wire packets this entry saw, 1 when
// nothing was sampled
func (e FlowEntry) SamplingProbability() float64 {
	if e.EstPackets == 0 {
		return 1
	}
	return float64(e.Packets) / float64(e.EstPackets)
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
