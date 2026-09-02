package collector

// IPFIX flowEndReason values from the IANA registry (information element 136)
// idle timeout marks a flow that went quiet, end of flow is reserved for a
// protocol level end such as TCP FIN, forced end covers agent shutdown, and
// lack of resources covers eviction because the flow table is full
const (
	FlowEndReasonIdleTimeout     uint8 = 0x01
	FlowEndReasonEndOfFlow       uint8 = 0x03
	FlowEndReasonForcedEnd       uint8 = 0x04
	FlowEndReasonLackOfResources uint8 = 0x05
)

// ExportedFlow is a completed flow ready for downstream export
type ExportedFlow struct {
	Key       FlowKey
	Entry     FlowEntry
	EndReason uint8
}

// FlowExporter consumes completed flows
type FlowExporter interface {
	ExportFlow(flow ExportedFlow) error
}
