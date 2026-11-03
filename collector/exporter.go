package collector

import "time"

// IPFIX flowEndReason values, IANA IE 136
const (
	FlowEndReasonIdleTimeout     uint8 = 0x01
	FlowEndReasonActiveTimeout   uint8 = 0x02
	FlowEndReasonForcedEnd       uint8 = 0x04
	FlowEndReasonLackOfResources uint8 = 0x05
)

// ExportedFlow is one delta record with boot times, pointer free for a queue the gc need not scan
type ExportedFlow struct {
	SrcAddr [16]byte
	DstAddr [16]byte
	Start   time.Duration
	End     time.Duration
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
