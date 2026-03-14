//go:build linux

package testutil

import (
	"runtime"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// NS is an isolated network namespace with a veth pair
type NS struct {
	veth *netlink.Veth
	Link netlink.Link
}

func NewNS(t *testing.T) *NS {
	t.Helper()

	runtime.LockOSThread()

	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}

	ns, err := netns.New()
	if err != nil {
		orig.Close()
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
		t.Fatal(err)
	}

	// bring both ends up
	for _, name := range []string{"rfm0", "rfm1", "lo"} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
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
	}
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

	peer, err := netlink.LinkByName("rfm1")
	if err != nil {
		t.Fatal(err)
	}

	fd, err := syscall.Socket(
		syscall.AF_PACKET, syscall.SOCK_RAW,
		int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)

	addr := &syscall.SockaddrLinklayer{
		Ifindex: peer.Attrs().Index,
	}
	if err := syscall.Sendto(fd, pkt, 0, addr); err != nil {
		t.Fatal(err)
	}
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0x00ff
}
