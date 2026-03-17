package testutil

import (
	"encoding/binary"
	"net"
)

const (
	EthHdrLen  = 14
	VLANHdrLen = 4
	IPv4HdrLen = 20
	IPv6HdrLen = 40
	TCPHdrLen  = 20
	UDPHdrLen  = 8
)

const (
	EthPIPv4   = 0x0800
	EthPIPv6   = 0x86DD
	EthP8021Q  = 0x8100
	EthP8021AD = 0x88A8
)

// Eth builds a raw ethernet frame
func Eth(dst, src net.HardwareAddr, ethertype uint16, payload []byte) []byte {
	frame := make([]byte, EthHdrLen+len(payload))
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], ethertype)
	copy(frame[EthHdrLen:], payload)
	return frame
}

func defaultDstMAC() net.HardwareAddr {
	return net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
}

func defaultSrcMAC() net.HardwareAddr {
	return net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}
}

func addVLANTag(payload []byte, tci, inner uint16) []byte {
	frame := make([]byte, VLANHdrLen+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], tci)
	binary.BigEndian.PutUint16(frame[2:4], inner)
	copy(frame[VLANHdrLen:], payload)
	return frame
}

// IPv4 builds a minimal IPv4 header
// no options
// no checksum
func IPv4(proto uint8, src, dst net.IP, payload []byte) []byte {
	total := IPv4HdrLen + len(payload)
	hdr := make([]byte, total)
	hdr[0] = 0x45 // version=4, ihl=5
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	hdr[8] = 64 // ttl
	hdr[9] = proto
	copy(hdr[12:16], src.To4())
	copy(hdr[16:20], dst.To4())
	copy(hdr[IPv4HdrLen:], payload)
	return hdr
}

// TCP builds a minimal TCP header
// no options
// no checksum
func TCP(srcPort, dstPort uint16) []byte {
	hdr := make([]byte, TCPHdrLen)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	hdr[12] = 0x50 // data offset = 5
	return hdr
}

// UDP builds a minimal UDP header
// no checksum
func UDP(srcPort, dstPort uint16) []byte {
	hdr := make([]byte, UDPHdrLen)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint16(hdr[4:6], UDPHdrLen)
	return hdr
}

// IPv6 builds a minimal IPv6 header
// no extension headers
func IPv6(proto uint8, src, dst net.IP, payload []byte) []byte {
	total := IPv6HdrLen + len(payload)
	hdr := make([]byte, total)
	hdr[0] = 0x60 // version=6
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(payload)))
	hdr[6] = proto
	hdr[7] = 64 // hop limit
	copy(hdr[8:24], src.To16())
	copy(hdr[24:40], dst.To16())
	copy(hdr[IPv6HdrLen:], payload)
	return hdr
}

// IPv4WithOptions builds an IPv4 header with options
// padded to a 4-byte boundary
func IPv4WithOptions(proto uint8, src, dst net.IP, options, payload []byte) []byte {
	optLen := len(options)
	padLen := (4 - optLen%4) % 4
	ihl := 5 + (optLen+padLen)/4
	hdrLen := ihl * 4
	total := hdrLen + len(payload)
	hdr := make([]byte, total)
	hdr[0] = byte(0x40 | ihl)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	hdr[8] = 64 // ttl
	hdr[9] = proto
	copy(hdr[12:16], src.To4())
	copy(hdr[16:20], dst.To4())
	copy(hdr[20:20+optLen], options)
	copy(hdr[hdrLen:], payload)
	return hdr
}

// IPv4Fragment builds a minimal IPv4 fragment header.
// offsetBytes must be a multiple of 8.
func IPv4Fragment(proto uint8, src, dst net.IP, id uint16, offsetBytes uint16, more bool, payload []byte) []byte {
	if offsetBytes%8 != 0 {
		panic("offsetBytes must be a multiple of 8")
	}

	total := IPv4HdrLen + len(payload)
	hdr := make([]byte, total)
	hdr[0] = 0x45 // version=4, ihl=5
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	binary.BigEndian.PutUint16(hdr[4:6], id)

	frag := offsetBytes / 8
	if more {
		frag |= 0x2000
	}
	binary.BigEndian.PutUint16(hdr[6:8], frag)

	hdr[8] = 64 // ttl
	hdr[9] = proto
	copy(hdr[12:16], src.To4())
	copy(hdr[16:20], dst.To4())
	copy(hdr[IPv4HdrLen:], payload)
	return hdr
}

// EthIPv4TCPWithOptions builds an eth+ipv4+tcp frame with IP options
func EthIPv4TCPWithOptions(srcIP, dstIP net.IP, srcPort, dstPort uint16, options []byte) []byte {
	tcp := TCP(srcPort, dstPort)
	ip := IPv4WithOptions(6, srcIP, dstIP, options, tcp)
	return Eth(
		defaultDstMAC(),
		defaultSrcMAC(),
		EthPIPv4,
		ip,
	)
}

// EthIPv4TCP builds a complete eth+ipv4+tcp frame
func EthIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	tcp := TCP(srcPort, dstPort)
	ip := IPv4(6, srcIP, dstIP, tcp) // proto 6 = TCP
	return Eth(
		defaultDstMAC(),
		defaultSrcMAC(),
		EthPIPv4, // eth p ip
		ip,
	)
}

// EthVLANIPv4TCP builds an 802.1Q tagged eth+ipv4+tcp frame
func EthVLANIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16, tci uint16) []byte {
	tcp := TCP(srcPort, dstPort)
	ip := IPv4(6, srcIP, dstIP, tcp)
	return Eth(
		defaultDstMAC(),
		defaultSrcMAC(),
		EthP8021Q,
		addVLANTag(ip, tci, EthPIPv4),
	)
}

// EthIPv4UDP builds a complete eth+ipv4+udp frame
func EthIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	udp := UDP(srcPort, dstPort)
	ip := IPv4(17, srcIP, dstIP, udp) // proto 17 = UDP
	return Eth(
		defaultDstMAC(),
		defaultSrcMAC(),
		EthPIPv4, // eth p ip
		ip,
	)
}

// EthIPv4UDPFragment builds an eth+ipv4 fragment frame for UDP traffic.
func EthIPv4UDPFragment(srcIP, dstIP net.IP, id uint16, offsetBytes uint16, more bool, payload []byte) []byte {
	ip := IPv4Fragment(17, srcIP, dstIP, id, offsetBytes, more, payload)
	return Eth(
		defaultDstMAC(),
		defaultSrcMAC(),
		EthPIPv4,
		ip,
	)
}

// EthIPv6TCP builds a complete eth+ipv6+tcp frame
func EthIPv6TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	tcp := TCP(srcPort, dstPort)
	ip := IPv6(6, srcIP, dstIP, tcp) // proto 6 = TCP
	return Eth(
		defaultDstMAC(),
		defaultSrcMAC(),
		EthPIPv6, // eth p ipv6
		ip,
	)
}

// EthQinQIPv6UDP builds an 802.1ad + 802.1Q tagged eth+ipv6+udp frame
func EthQinQIPv6UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, outerTCI, innerTCI uint16) []byte {
	udp := UDP(srcPort, dstPort)
	ip := IPv6(17, srcIP, dstIP, udp)
	vlan := addVLANTag(ip, innerTCI, EthPIPv6)
	return Eth(
		defaultDstMAC(),
		defaultSrcMAC(),
		EthP8021AD,
		addVLANTag(vlan, outerTCI, EthP8021Q),
	)
}

// EthIPv6UDP builds a complete eth+ipv6+udp frame
func EthIPv6UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	udp := UDP(srcPort, dstPort)
	ip := IPv6(17, srcIP, dstIP, udp) // proto 17 = UDP
	return Eth(
		defaultDstMAC(),
		defaultSrcMAC(),
		EthPIPv6, // eth p ipv6
		ip,
	)
}
