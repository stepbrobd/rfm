package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"structs"
)

const wireFlowEventSize = 64

// wireFlowEvent mirrors struct rfm_flow_event in bpf/rfm_common.h
type wireFlowEvent struct {
	_       structs.HostLayout
	Tstamp  uint64
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	Segs    uint16
	SrcAddr [16]uint8
	DstAddr [16]uint8
	SrcPort uint16
	DstPort uint16
	Len     uint32
	L2Len   uint8
	_       [7]uint8
}

// DecodeFlowEvent decodes one ring buffer record and refuses an event the
// probe does not emit, so the methods of FlowEvent can rely on its fields
func DecodeFlowEvent(raw []byte) (FlowEvent, error) {
	if len(raw) < wireFlowEventSize {
		return FlowEvent{}, fmt.Errorf("short flow event: %d < %d bytes", len(raw), wireFlowEventSize)
	}

	var wire wireFlowEvent
	if _, err := binary.Decode(raw, binary.NativeEndian, &wire); err != nil {
		return FlowEvent{}, fmt.Errorf("decode flow event: %w", err)
	}

	ev := FlowEvent{
		Tstamp:  wire.Tstamp,
		Ifindex: wire.Ifindex,
		Dir:     wire.Dir,
		Proto:   wire.Proto,
		SrcAddr: netip.AddrFrom16(wire.SrcAddr),
		DstAddr: netip.AddrFrom16(wire.DstAddr),
		SrcPort: wire.SrcPort,
		DstPort: wire.DstPort,
		Segs:    wire.Segs,
		Len:     wire.Len,
		L2Len:   wire.L2Len,
	}
	// every skb stands for at least one wire packet, and the probe counts
	// the l2 header of every wire packet in len
	if ev.Segs == 0 {
		return FlowEvent{}, errors.New("flow event without wire packets")
	}
	if l2 := ev.Packets() * uint64(ev.L2Len); l2 > uint64(ev.Len) {
		return FlowEvent{}, fmt.Errorf("flow event with %d bytes of l2 headers in %d wire bytes", l2, ev.Len)
	}
	return ev, nil
}
