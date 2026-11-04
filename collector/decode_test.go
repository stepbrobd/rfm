package collector

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestDecodeFlowEvent(t *testing.T) {
	want := FlowEvent{
		Tstamp:  123456789,
		Ifindex: 42,
		Dir:     1,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
		Segs:    3,
		Len:     1500,
		L2Len:   18,
	}

	wire := wireFlowEvent{
		Tstamp:  uint64(want.Tstamp),
		Ifindex: want.Ifindex,
		Proto:   want.Proto,
		DirL2:   want.Dir<<dirShift | want.L2Len,
		SrcAddr: want.SrcAddr.As16(),
		DstAddr: want.DstAddr.As16(),
		SrcPort: want.SrcPort,
		DstPort: want.DstPort,
		Segs:    want.Segs,
		Len:     want.Len,
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, &wire); err != nil {
		t.Fatal(err)
	}
	// with the 8 byte ring header a record of struct rfm_flow_event fills one cache line
	if buf.Len() != 56 {
		t.Fatalf("wire event is %d bytes, want the 56 of struct rfm_flow_event", buf.Len())
	}

	got, err := DecodeFlowEvent(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDecodeFlowEventShort(t *testing.T) {
	_, err := DecodeFlowEvent(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short input")
	}

	if _, err := DecodeFlowEvent(make([]byte, 55)); err == nil {
		t.Fatal("expected error for an event without its last byte")
	}
}

func TestDecodeFlowEventRefusesEventsTheProbeCannotEmit(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   FlowEvent
	}{
		// every skb stands for at least one wire packet
		{"no wire packets", FlowEvent{Len: 100}},
		// the probe counts the l2 header of every wire packet in len
		{"l2 headers past the wire bytes", FlowEvent{Segs: 2, Len: 20, L2Len: 14}},
	} {
		if ev, err := DecodeFlowEvent(encodeWireEvent(tc.ev)); err == nil {
			t.Errorf("%s: decoded %+v, want it refused", tc.name, ev)
		}
	}
}

// encodeWireEvent encodes a FlowEvent into wire format for testing
// used by Run tests in collector_test.go
func encodeWireEvent(ev FlowEvent) []byte {
	wire := wireFlowEvent{
		Tstamp:  uint64(ev.Tstamp),
		Ifindex: ev.Ifindex,
		Proto:   ev.Proto,
		DirL2:   ev.Dir<<dirShift | ev.L2Len,
		SrcAddr: ev.SrcAddr.As16(),
		DstAddr: ev.DstAddr.As16(),
		SrcPort: ev.SrcPort,
		DstPort: ev.DstPort,
		Segs:    ev.Segs,
		Len:     ev.Len,
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.NativeEndian, &wire)
	return buf.Bytes()
}
