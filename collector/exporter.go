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
// Entry carries the packets and bytes seen since the previous record of the
// same flow, with FirstSeen at the start of that interval, so a long lived
// flow exported on the active timeout turns into a chain of delta records
// that a collector sums
type ExportedFlow struct {
	Key       FlowKey
	Entry     FlowEntry
	EndReason uint8
}

// FlowExporter consumes completed flows
type FlowExporter interface {
	ExportFlow(flow ExportedFlow) error
}
