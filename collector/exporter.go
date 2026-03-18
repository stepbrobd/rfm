package collector

// IPFIX flow end reason values from the IANA registry
const (
	FlowEndReasonIdleTimeout uint8 = 0x01
	FlowEndReasonEndOfFlow   uint8 = 0x03
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
