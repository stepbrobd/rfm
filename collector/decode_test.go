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
		Len:     1500,
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
		Len:     want.Len,
	}

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, &wire); err != nil {
		t.Fatal(err)
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
}

// encodeWireEvent encodes a FlowEvent into wire format for testing.
// Used by Run tests in collector_test.go.
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
		Len:     ev.Len,
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.NativeEndian, &wire)
	return buf.Bytes()
}
