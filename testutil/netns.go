//go:build linux

package testutil

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// virtio_net_hdr values understood by AF_PACKET sockets with PACKET_VNET_HDR
const (
	virtioNetHdrLen        = 10
	virtioNetHdrNeedsCsum  = 1
	virtioNetHdrGSOTCPv4   = 1
	virtioNetHdrGSOTCPv6   = 4
	tcpChecksumOffset      = 16
	packetVNetHdrSockopt   = unix.PACKET_VNET_HDR
	packetVNetHdrSockLevel = unix.SOL_PACKET
)

// NS is an isolated network namespace with a veth pair
type NS struct {
	veth *netlink.Veth
	Link netlink.Link
	ns   netns.NsHandle
}

func NewNS(t *testing.T) *NS {
	t.Helper()

	runtime.LockOSThread()

	orig, err := netns.Get()
	if err != nil {
		SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}

	ns, err := netns.New()
	if err != nil {
		orig.Close()
		SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}

	// register cleanup early so failures below still restore ns
	t.Cleanup(func() {
		netns.Set(orig)
		ns.Close()
		orig.Close()
		runtime.UnlockOSThread()
	})

	// create veth pair inside the namespace
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "rfm0"},
		PeerName:  "rfm1",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}

	// bring both ends up
	for _, name := range []string{"rfm0", "rfm1", "lo"} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			SkipIfUnprivileged(t, err)
			t.Fatal(err)
		}
	}

	link, err := netlink.LinkByName("rfm0")
	if err != nil {
		t.Fatal(err)
	}

	return &NS{
		veth: veth,
		Link: link,
		ns:   ns,
	}
}

// Handle returns the namespace so another goroutine can enter it with
// runtime.LockOSThread and netns.Set
func (n *NS) Handle() netns.NsHandle {
	return n.ns
}

func (n *NS) Ifindex() int {
	return n.Link.Attrs().Index
}

func (n *NS) Name() string {
	return n.Link.Attrs().Name
}

// SendRaw sends a raw packet out rfm1 (peer end of veth)
// so it arrives on rfm0 as ingress
func (n *NS) SendRaw(t *testing.T, pkt []byte) {
	t.Helper()

	n.SendRawOn(t, "rfm1", pkt)
}

// SendRawOn sends a raw packet out the named interface, use the monitored
// end to have it leave through its egress hook
func (n *NS) SendRawOn(t *testing.T, ifname string, pkt []byte) {
	t.Helper()

	dev, err := netlink.LinkByName(ifname)
	if err != nil {
		t.Fatal(err)
	}

	fd, err := syscall.Socket(
		syscall.AF_PACKET, syscall.SOCK_RAW,
		int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer syscall.Close(fd)

	addr := &syscall.SockaddrLinklayer{
		Ifindex: dev.Attrs().Index,
	}
	if err := syscall.Sendto(fd, pkt, 0, addr); err != nil {
		SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
}

// SendGSO hands the kernel one TCP GSO skb built from pkt, an IPv4 or IPv6
// ethernet frame whose TCP payload is longer than gsoSize, the same way a
// virtio or tap driver delivers a large frame, so the tc hooks see an skb
// that stands for several wire packets
// the skb leaves through the named interface, use the peer name to have it
// arrive on the monitored end as ingress
// hdrLen is the ethernet + ip + tcp header size of pkt, IPv6 extension
// headers included
func (n *NS) SendGSO(t *testing.T, ifname string, pkt []byte, hdrLen, gsoSize uint16) {
	t.Helper()

	dev, err := netlink.LinkByName(ifname)
	if err != nil {
		t.Fatal(err)
	}

	fd, err := syscall.Socket(
		syscall.AF_PACKET, syscall.SOCK_RAW,
		int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		SkipIfUnprivileged(t, err)
		t.Fatal(err)
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptInt(fd, packetVNetHdrSockLevel, packetVNetHdrSockopt, 1); err != nil {
		t.Fatalf("PACKET_VNET_HDR: %v", err)
	}

	// struct virtio_net_hdr, little endian on AF_PACKET
	// the checksum fields locate the tcp checksum so the kernel accepts
	// the frame as a partial checksum gso skb
	hdr := make([]byte, virtioNetHdrLen)
	hdr[0] = virtioNetHdrNeedsCsum
	hdr[1] = virtioNetHdrGSOTCPv4
	if binary.BigEndian.Uint16(pkt[12:14]) == EthPIPv6 {
		hdr[1] = virtioNetHdrGSOTCPv6
	}
	binary.LittleEndian.PutUint16(hdr[2:4], hdrLen)
	binary.LittleEndian.PutUint16(hdr[4:6], gsoSize)
	binary.LittleEndian.PutUint16(hdr[6:8], hdrLen-TCPHdrLen)
	binary.LittleEndian.PutUint16(hdr[8:10], tcpChecksumOffset)

	addr := &syscall.SockaddrLinklayer{
		Ifindex: dev.Attrs().Index,
	}
	if err := syscall.Sendto(fd, append(hdr, pkt...), 0, addr); err != nil {
		SkipIfUnprivileged(t, err)
		t.Fatalf("send gso frame: %v", err)
	}
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}
