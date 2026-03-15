package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"structs"
)

const wireFlowEventSize = 48

type wireFlowEvent struct {
	_       structs.HostLayout
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	Pad     uint16
	SrcAddr [16]uint8
	DstAddr [16]uint8
	SrcPort uint16
	DstPort uint16
	Len     uint32
}

func DecodeFlowEvent(raw []byte) (FlowEvent, error) {
	if len(raw) < wireFlowEventSize {
		return FlowEvent{}, fmt.Errorf("short flow event: %d < %d bytes", len(raw), wireFlowEventSize)
	}

	var wire wireFlowEvent
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &wire); err != nil {
		return FlowEvent{}, fmt.Errorf("decode flow event: %w", err)
	}

	return FlowEvent{
		Ifindex: wire.Ifindex,
		Dir:     wire.Dir,
		Proto:   wire.Proto,
		SrcAddr: netip.AddrFrom16(wire.SrcAddr),
		DstAddr: netip.AddrFrom16(wire.DstAddr),
		SrcPort: wire.SrcPort,
		DstPort: wire.DstPort,
		Len:     wire.Len,
	}, nil
}
