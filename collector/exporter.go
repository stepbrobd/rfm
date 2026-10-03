package collector

// IPFIX flowEndReason values from the IANA registry (information element 136)
// idle timeout marks a flow that went quiet, active timeout marks an interval
// record for a flow that keeps going, end of flow is reserved for a protocol
// level end such as TCP FIN, forced end covers agent shutdown, and lack of
// resources covers eviction because the flow table is full
const (
	FlowEndReasonIdleTimeout     uint8 = 0x01
	FlowEndReasonActiveTimeout   uint8 = 0x02
	FlowEndReasonEndOfFlow       uint8 = 0x03
	FlowEndReasonForcedEnd       uint8 = 0x04
	FlowEndReasonLackOfResources uint8 = 0x05
)

// ExportedFlow is one flow record ready for downstream export
// it carries the packets and bytes seen since the previous record of the same
// flow, Start and End are the first and last of those packets, so a long
// lived flow exported on the active timeout turns into a chain of delta
// records that a collector sums
// it holds no pointers, the addresses are 16 bytes with IPv4 mapped as the
// probe reports them and the times unix nanoseconds, so a queue of records
// costs the garbage collector nothing to scan
type ExportedFlow struct {
	SrcAddr [16]byte
	DstAddr [16]byte
	Start   int64
	End     int64
	// Packets counts the sampled wire packets, Octets their IP bytes, header
	// plus payload, and EstPackets the packets they stand for, which gives
	// the sampling probability of the record
	Packets    uint64
	Octets     uint64
	EstPackets uint64
	Ifindex    uint32
	SrcPort    uint16
	DstPort    uint16
	Dir        uint8
	Proto      uint8
	EndReason  uint8
}

// SamplingProbability is the share of wire packets the record saw, 1 when
// nothing was sampled
func (f ExportedFlow) SamplingProbability() float64 {
	if f.EstPackets == 0 {
		return 1
	}
	return float64(f.Packets) / float64(f.EstPackets)
}

// FlowExporter consumes completed flows
// it counts the flows it refuses, the collector only logs the errors
type FlowExporter interface {
	ExportFlow(flow ExportedFlow) error
}
