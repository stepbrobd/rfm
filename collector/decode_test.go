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
		Tstamp:  want.Tstamp,
		Ifindex: want.Ifindex,
		Dir:     want.Dir,
		Proto:   want.Proto,
		SrcAddr: want.SrcAddr.As16(),
		DstAddr: want.DstAddr.As16(),
		SrcPort: want.SrcPort,
		DstPort: want.DstPort,
		Segs:    want.Segs,
		Len:     want.Len,
		L2Len:   want.L2Len,
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, &wire); err != nil {
		t.Fatal(err)
	}
	// struct rfm_flow_event is padded to a multiple of its 8 byte alignment
	if buf.Len() != 64 {
		t.Fatalf("wire event is %d bytes, want the 64 of struct rfm_flow_event", buf.Len())
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

	// an event without the L2 length is from another build of the program
	if _, err := DecodeFlowEvent(make([]byte, 56)); err == nil {
		t.Fatal("expected error for an event without the l2 length")
	}
}

func TestDecodeFlowEventRefusesEventsTheProbeCannotEmit(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   FlowEvent
	}{
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
		Tstamp:  ev.Tstamp,
		Ifindex: ev.Ifindex,
		Dir:     ev.Dir,
		Proto:   ev.Proto,
		SrcAddr: ev.SrcAddr.As16(),
		DstAddr: ev.DstAddr.As16(),
		SrcPort: ev.SrcPort,
		DstPort: ev.DstPort,
		Segs:    ev.Segs,
		Len:     ev.Len,
		L2Len:   ev.L2Len,
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.NativeEndian, &wire)
	return buf.Bytes()
}
