package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"structs"
	"time"
	"unsafe"
)

const wireFlowEventSize = int(unsafe.Sizeof(wireFlowEvent{}))

// wireFlowEvent mirrors struct rfm_flow_event in bpf/rfm_common.h
type wireFlowEvent struct {
	_       structs.HostLayout
	Tstamp  uint64
	Ifindex uint32
	Proto   uint8
	DirL2   uint8
	Segs    uint16
	SrcAddr [16]uint8
	DstAddr [16]uint8
	SrcPort uint16
	DstPort uint16
	Len     uint32
}

// binary.Decode walks the struct by reflection per record
const (
	offTstamp  = unsafe.Offsetof(wireFlowEvent{}.Tstamp)
	offIfindex = unsafe.Offsetof(wireFlowEvent{}.Ifindex)
	offProto   = unsafe.Offsetof(wireFlowEvent{}.Proto)
	offDirL2   = unsafe.Offsetof(wireFlowEvent{}.DirL2)
	offSegs    = unsafe.Offsetof(wireFlowEvent{}.Segs)
	offSrcAddr = unsafe.Offsetof(wireFlowEvent{}.SrcAddr)
	offDstAddr = unsafe.Offsetof(wireFlowEvent{}.DstAddr)
	offSrcPort = unsafe.Offsetof(wireFlowEvent{}.SrcPort)
	offDstPort = unsafe.Offsetof(wireFlowEvent{}.DstPort)
	offLen     = unsafe.Offsetof(wireFlowEvent{}.Len)
)

// DirL2 holds the direction in its top bit and the l2 header of each wire packet in the low 7
const (
	dirShift  = 7
	l2LenMask = 1<<dirShift - 1
)

// DecodeFlowEvent decodes one ring buffer record and refuses an event the
// probe does not emit, so the methods of FlowEvent can rely on its fields,
// the coarse monotonic stamp of the record becomes boot time
func DecodeFlowEvent(raw []byte) (FlowEvent, error) {
	if len(raw) < wireFlowEventSize {
		return FlowEvent{}, fmt.Errorf("short flow event: %d < %d bytes", len(raw), wireFlowEventSize)
	}

	ne := binary.NativeEndian
	ev := FlowEvent{
		Tstamp:  time.Duration(ne.Uint64(raw[offTstamp:])) + suspended(),
		Ifindex: ne.Uint32(raw[offIfindex:]),
		Dir:     raw[offDirL2] >> dirShift,
		Proto:   raw[offProto],
		SrcAddr: netip.AddrFrom16([16]byte(raw[offSrcAddr:])),
		DstAddr: netip.AddrFrom16([16]byte(raw[offDstAddr:])),
		SrcPort: ne.Uint16(raw[offSrcPort:]),
		DstPort: ne.Uint16(raw[offDstPort:]),
		Segs:    ne.Uint16(raw[offSegs:]),
		Len:     ne.Uint32(raw[offLen:]),
		L2Len:   raw[offDirL2] & l2LenMask,
	}
	if err := checkCounts(ev.Segs, ev.L2Len, ev.Len); err != nil {
		return FlowEvent{}, err
	}
	return ev, nil
}

// checkCounts refuses counts the probe cannot emit, every skb stands for at
// least one wire packet and the probe counts the l2 header of every wire
// packet in its wire bytes
func checkCounts(segs uint16, l2Len uint8, wire uint32) error {
	if segs == 0 {
		return errors.New("flow event without wire packets")
	}
	if l2 := uint64(segs) * uint64(l2Len); l2 > uint64(wire) {
		return fmt.Errorf("flow event with %d bytes of l2 headers in %d wire bytes", l2, wire)
	}
	return nil
}

// sample is one record as the run loop decodes it, 64 bytes, its table key
// is written at decode so the lookup a batch later reads it from memory
type sample struct {
	tstamp time.Duration
	len    uint32
	segs   uint16
	l2Len  uint8
	id     flowID
}

// decode fills s from one ring buffer record and refuses what DecodeFlowEvent refuses
func (s *sample) decode(raw []byte) error {
	if len(raw) < wireFlowEventSize {
		return fmt.Errorf("short flow event: %d < %d bytes", len(raw), wireFlowEventSize)
	}
	ne := binary.NativeEndian
	s.tstamp = time.Duration(ne.Uint64(raw[offTstamp:]))
	s.len = ne.Uint32(raw[offLen:])
	s.segs = ne.Uint16(raw[offSegs:])
	s.l2Len = raw[offDirL2] & l2LenMask
	s.id.dir = raw[offDirL2] >> dirShift
	s.id.proto = raw[offProto]
	copy(s.id.ifindex[:], raw[offIfindex:])
	// the destination follows the source in both the record and the key
	copy(s.id.addrs[:], raw[offSrcAddr:offDstAddr+16])
	copy(s.id.ports[:], raw[offSrcPort:offDstPort+2])
	return checkCounts(s.segs, s.l2Len, s.len)
}

// from fills s from ev
func (s *sample) from(ev *FlowEvent) {
	s.tstamp, s.len, s.segs, s.l2Len = ev.Tstamp, ev.Len, ev.Segs, ev.L2Len
	s.id = ev.Key().id()
}
