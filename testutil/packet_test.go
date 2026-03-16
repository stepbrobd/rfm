package testutil

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestUDP(t *testing.T) {
	hdr := UDP(12345, 80)

	if len(hdr) != UDPHdrLen {
		t.Fatalf("want len %d, got %d", UDPHdrLen, len(hdr))
	}

	srcPort := binary.BigEndian.Uint16(hdr[0:2])
	if srcPort != 12345 {
		t.Fatalf("want src port 12345, got %d", srcPort)
	}

	dstPort := binary.BigEndian.Uint16(hdr[2:4])
	if dstPort != 80 {
		t.Fatalf("want dst port 80, got %d", dstPort)
	}

	length := binary.BigEndian.Uint16(hdr[4:6])
	if length != UDPHdrLen {
		t.Fatalf("want length %d, got %d", UDPHdrLen, length)
	}
}

func TestIPv6(t *testing.T) {
	payload := []byte{0xaa, 0xbb}
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")
	proto := uint8(6) // tcp

	hdr := IPv6(proto, src, dst, payload)

	if len(hdr) != IPv6HdrLen+len(payload) {
		t.Fatalf("want len %d, got %d", IPv6HdrLen+len(payload), len(hdr))
	}

	// version nibble must be 6
	version := hdr[0] >> 4
	if version != 6 {
		t.Fatalf("want version 6, got %d", version)
	}

	// next header
	if hdr[6] != proto {
		t.Fatalf("want next header %d, got %d", proto, hdr[6])
	}

	// payload length
	pLen := binary.BigEndian.Uint16(hdr[4:6])
	if pLen != uint16(len(payload)) {
		t.Fatalf("want payload length %d, got %d", len(payload), pLen)
	}
}

func TestEthIPv4UDP(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")

	frame := EthIPv4UDP(src, dst, 1234, 53)

	wantLen := EthHdrLen + IPv4HdrLen + UDPHdrLen
	if len(frame) != wantLen {
		t.Fatalf("want len %d, got %d", wantLen, len(frame))
	}

	// ethertype
	ethertype := binary.BigEndian.Uint16(frame[12:14])
	if ethertype != 0x0800 {
		t.Fatalf("want ethertype 0x0800, got 0x%04x", ethertype)
	}

	// ip proto = 17
	ipProto := frame[EthHdrLen+9]
	if ipProto != 17 {
		t.Fatalf("want IP proto 17, got %d", ipProto)
	}
}

func TestEthVLANIPv4TCP(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")

	frame := EthVLANIPv4TCP(src, dst, 1234, 443, 42)

	wantLen := EthHdrLen + VLANHdrLen + IPv4HdrLen + TCPHdrLen
	if len(frame) != wantLen {
		t.Fatalf("want len %d, got %d", wantLen, len(frame))
	}

	outer := binary.BigEndian.Uint16(frame[12:14])
	if outer != EthP8021Q {
		t.Fatalf("want outer ethertype 0x%04x, got 0x%04x", EthP8021Q, outer)
	}

	tci := binary.BigEndian.Uint16(frame[14:16])
	if tci != 42 {
		t.Fatalf("want vlan id 42, got %d", tci)
	}

	inner := binary.BigEndian.Uint16(frame[16:18])
	if inner != EthPIPv4 {
		t.Fatalf("want inner ethertype 0x%04x, got 0x%04x", EthPIPv4, inner)
	}
}

func TestIPv4WithOptions(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")
	options := []byte{0x01, 0x01, 0x01, 0x01} // 4 nop options
	payload := []byte{0xaa, 0xbb}

	hdr := IPv4WithOptions(6, src, dst, options, payload)

	// ihl should be 6
	ihl := hdr[0] & 0x0f
	if ihl != 6 {
		t.Fatalf("ihl = %d, want 6", ihl)
	}

	// total length
	total := binary.BigEndian.Uint16(hdr[2:4])
	if total != 24+2 {
		t.Fatalf("total length = %d, want %d", total, 24+2)
	}

	// protocol
	if hdr[9] != 6 {
		t.Fatalf("proto = %d, want 6", hdr[9])
	}

	// payload starts at offset 24
	if hdr[24] != 0xaa || hdr[25] != 0xbb {
		t.Fatalf("payload = %x %x, want aa bb", hdr[24], hdr[25])
	}
}

func TestEthIPv6TCP(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	frame := EthIPv6TCP(src, dst, 4000, 443)

	wantLen := EthHdrLen + IPv6HdrLen + TCPHdrLen
	if len(frame) != wantLen {
		t.Fatalf("want len %d, got %d", wantLen, len(frame))
	}

	// ethertype
	ethertype := binary.BigEndian.Uint16(frame[12:14])
	if ethertype != 0x86DD {
		t.Fatalf("want ethertype 0x86DD, got 0x%04x", ethertype)
	}
}

func TestEthQinQIPv6UDP(t *testing.T) {
	src := net.ParseIP("fd00::1")
	dst := net.ParseIP("fd00::2")

	frame := EthQinQIPv6UDP(src, dst, 4000, 53, 100, 200)

	wantLen := EthHdrLen + 2*VLANHdrLen + IPv6HdrLen + UDPHdrLen
	if len(frame) != wantLen {
		t.Fatalf("want len %d, got %d", wantLen, len(frame))
	}

	outer := binary.BigEndian.Uint16(frame[12:14])
	if outer != EthP8021AD {
		t.Fatalf("want outer ethertype 0x%04x, got 0x%04x", EthP8021AD, outer)
	}

	outerTCI := binary.BigEndian.Uint16(frame[14:16])
	if outerTCI != 100 {
		t.Fatalf("want outer vlan id 100, got %d", outerTCI)
	}

	middle := binary.BigEndian.Uint16(frame[16:18])
	if middle != EthP8021Q {
		t.Fatalf("want inner tag ethertype 0x%04x, got 0x%04x", EthP8021Q, middle)
	}

	innerTCI := binary.BigEndian.Uint16(frame[18:20])
	if innerTCI != 200 {
		t.Fatalf("want inner vlan id 200, got %d", innerTCI)
	}

	inner := binary.BigEndian.Uint16(frame[20:22])
	if inner != EthPIPv6 {
		t.Fatalf("want payload ethertype 0x%04x, got 0x%04x", EthPIPv6, inner)
	}
}
