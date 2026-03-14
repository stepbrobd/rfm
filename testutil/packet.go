package testutil

import (
	"encoding/binary"
	"net"
)

const (
	EthHdrLen  = 14
	IPv4HdrLen = 20
	TCPHdrLen  = 20
	UDPHdrLen  = 8
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

// IPv4 builds a minimal IPv4 header (no options, no checksum)
func IPv4(proto uint8, src, dst net.IP, payload []byte) []byte {
	total := IPv4HdrLen + len(payload)
	hdr := make([]byte, total)
	hdr[0] = 0x45 // version=4, ihl=5
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	hdr[8] = 64 // TTL
	hdr[9] = proto
	copy(hdr[12:16], src.To4())
	copy(hdr[16:20], dst.To4())
	copy(hdr[IPv4HdrLen:], payload)
	return hdr
}

// TCP builds a minimal TCP header (no options, no checksum)
func TCP(srcPort, dstPort uint16) []byte {
	hdr := make([]byte, TCPHdrLen)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	hdr[12] = 0x50 // data offset = 5 (20 bytes)
	return hdr
}

// EthIPv4TCP builds a complete eth+ipv4+tcp frame
func EthIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	tcp := TCP(srcPort, dstPort)
	ip := IPv4(6, srcIP, dstIP, tcp) // proto 6 = TCP
	return Eth(
		net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02},
		0x0800, // ETH_P_IP
		ip,
	)
}
