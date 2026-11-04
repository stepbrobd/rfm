package collector

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// Enricher labels flow addresses, it runs without the collector lock and may run concurrently
type Enricher interface {
	Enrich(src, dst netip.Addr) (srcLabels, dstLabels Labels)
}

// Labels holds enrichment metadata for a single address
type Labels struct {
	ASN  uint32
	City string
}

// FlowEvent is one sampled skb of Segs wire packets and Len wire bytes, L2Len per packet
type FlowEvent struct {
	Tstamp  time.Duration // CLOCK_BOOTTIME
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
	Segs    uint16
	Len     uint32
	L2Len   uint8
}

// Packets returns the number of wire packets the event stands for
func (e FlowEvent) Packets() uint64 {
	return uint64(e.Segs)
}

// IPBytes returns the ip bytes of the event, DecodeFlowEvent ensures its l2 headers fit in Len
func (e FlowEvent) IPBytes() uint64 {
	return uint64(e.Len) - e.Packets()*uint64(e.L2Len)
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

// flowID is a flow's key in the flow table, plain bytes the map hashes and compares in one pass
type flowID struct {
	// addrs holds the source then the destination address in their 16 byte form
	addrs [32]byte
	// ports holds the source then the destination port in host order
	ports   [4]byte
	ifindex [4]byte
	dir     uint8
	proto   uint8
}

// id returns the table key of k
func (k FlowKey) id() flowID {
	var id flowID
	src, dst := k.SrcAddr.As16(), k.DstAddr.As16()
	copy(id.addrs[:16], src[:])
	copy(id.addrs[16:], dst[:])
	ne := binary.NativeEndian
	ne.PutUint16(id.ports[:], k.SrcPort)
	ne.PutUint16(id.ports[2:], k.DstPort)
	ne.PutUint32(id.ifindex[:], k.Ifindex)
	id.dir, id.proto = k.Dir, k.Proto
	return id
}

// key returns the flow key of id, its addresses in their 16 byte form
func (id *flowID) key() FlowKey {
	ne := binary.NativeEndian
	return FlowKey{
		Ifindex: ne.Uint32(id.ifindex[:]),
		Dir:     id.dir,
		Proto:   id.proto,
		SrcAddr: netip.AddrFrom16([16]byte(id.addrs[:16])),
		DstAddr: netip.AddrFrom16([16]byte(id.addrs[16:])),
		SrcPort: ne.Uint16(id.ports[:]),
		DstPort: ne.Uint16(id.ports[2:]),
	}
}

// Direction returns the name of a Dir value
func Direction(dir uint8) string {
	if dir == 0 {
		return "ingress"
	}
	return "egress"
}

// FlowEntry counts a flow, the Est fields scale each event by its rate, IPBytes leave out l2 headers
type FlowEntry struct {
	// FirstSeen and LastSeen are CLOCK_BOOTTIME readings, BootEpoch dates them
	FirstSeen  time.Duration
	Packets    uint64
	Bytes      uint64
	IPBytes    uint64
	EstPackets uint64
	EstBytes   uint64
	LastSeen   time.Duration
	// Src and Dst are the enrichment labels resolved when the flow was
	// created, they stay fixed for the life of the flow
	Src Labels
	Dst Labels
}

// BootEpoch returns the wall time CLOCK_BOOTTIME counts from, read anew to follow clock steps
func BootEpoch() time.Time {
	return time.Now().Add(-bootNow())
}

// RollupKey is the label tuple of a flow series
type RollupKey struct {
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	Src     Labels
	Dst     Labels
}

// Counts are sampled packets and wire bytes with their estimates, every event
// scaled by the sample rate in force when it was sampled
type Counts struct {
	Packets    uint64
	Bytes      uint64
	EstPackets uint64
	EstBytes   uint64
}

func (c *Counts) add(o Counts) {
	c.Packets += o.Packets
	c.Bytes += o.Bytes
	c.EstPackets += o.EstPackets
	c.EstBytes += o.EstBytes
}

func (c *Counts) sub(o Counts) {
	c.Packets -= o.Packets
	c.Bytes -= o.Bytes
	c.EstPackets -= o.EstPackets
	c.EstBytes -= o.EstBytes
}

// counts returns the entry's counters without the IP bytes
func (e FlowEntry) counts() Counts {
	return Counts{Packets: e.Packets, Bytes: e.Bytes, EstPackets: e.EstPackets, EstBytes: e.EstBytes}
}

// Stats holds collector-level statistics
type Stats struct {
	ActiveFlows     uint64
	DroppedEvents   uint64
	ForcedEvictions uint64
	RingBufErrors   uint64
	BPFMapErrors    uint64
	// FoldedFlows counts the flows whose label tuple found no room under the
	// rollup cap and that count under empty enrichment labels instead
	FoldedFlows uint64
}
