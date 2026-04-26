package rib

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

func TestTableLookup(t *testing.T) {
	tab := NewTable()
	tab.Apply(Update{
		Reach: []Route{
			{
				Prefix:    netip.MustParsePrefix("203.0.113.0/24"),
				OriginASN: 64496,
			},
		},
	})

	route, ok := tab.Lookup(netip.MustParseAddr("203.0.113.42"))
	if !ok {
		t.Fatal("Lookup should find prefix")
	}
	if route.OriginASN != 64496 {
		t.Fatalf("OriginASN = %d, want 64496", route.OriginASN)
	}
}

func TestTableWithdraw(t *testing.T) {
	tab := NewTable()
	pfx := netip.MustParsePrefix("2001:db8::/32")
	tab.Apply(Update{
		Reach: []Route{
			{
				Prefix:    pfx,
				OriginASN: 64512,
			},
		},
	})
	tab.Apply(Update{
		Withdraw: []netip.Prefix{pfx},
	})

	if _, ok := tab.Lookup(netip.MustParseAddr("2001:db8::1")); ok {
		t.Fatal("Lookup should miss withdrawn prefix")
	}
}

func TestTableUnmapsIPv4(t *testing.T) {
	tab := NewTable()
	tab.Apply(Update{
		Reach: []Route{
			{
				Prefix:    netip.MustParsePrefix("198.51.100.0/24"),
				OriginASN: 64513,
			},
		},
	})

	route, ok := tab.Lookup(netip.MustParseAddr("::ffff:198.51.100.7"))
	if !ok {
		t.Fatal("Lookup should match mapped IPv4 address")
	}
	if route.OriginASN != 64513 {
		t.Fatalf("OriginASN = %d, want 64513", route.OriginASN)
	}
}

func TestTableEnrich(t *testing.T) {
	tab := NewTable()
	tab.Apply(Update{
		Reach: []Route{
			{
				Prefix:    netip.MustParsePrefix("203.0.113.0/24"),
				OriginASN: 64496,
				ASPath:    []uint32{64501, 64496},
			},
		},
	})

	src, dst := tab.Enrich(
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("203.0.113.7"),
	)

	if src.ASN != 0 {
		t.Fatalf("src ASN = %d, want 0", src.ASN)
	}
	if dst.ASN != 64496 {
		t.Fatalf("dst ASN = %d, want 64496", dst.ASN)
	}
}

func TestTableDedupesMetadata(t *testing.T) {
	tab := NewTable()

	tab.Apply(Update{
		Reach: []Route{
			{
				Prefix:      netip.MustParsePrefix("203.0.113.0/24"),
				OriginASN:   64496,
				ASPath:      []uint32{64501, 64496},
				Communities: []uint32{64501<<16 | 100},
				PeerASN:     64501,
				PeerAddress: netip.MustParseAddr("192.0.2.2"),
				PostPolicy:  true,
			},
			{
				Prefix:      netip.MustParsePrefix("203.0.114.0/24"),
				OriginASN:   64496,
				ASPath:      []uint32{64501, 64496},
				Communities: []uint32{64501<<16 | 100},
				PeerASN:     64501,
				PeerAddress: netip.MustParseAddr("192.0.2.2"),
				PostPolicy:  true,
			},
		},
	})

	if got := len(tab.metas); got != 1 {
		t.Fatalf("metadata entries = %d, want 1", got)
	}

	tab.Apply(Update{
		Withdraw: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	})
	if got := len(tab.metas); got != 1 {
		t.Fatalf("metadata entries after single withdraw = %d, want 1", got)
	}

	tab.Apply(Update{
		Withdraw: []netip.Prefix{netip.MustParsePrefix("203.0.114.0/24")},
	})
	if got := len(tab.metas); got != 0 {
		t.Fatalf("metadata entries after full withdraw = %d, want 0", got)
	}
}

func TestLookupClonesMetadata(t *testing.T) {
	tab := NewTable()
	tab.Apply(Update{
		Reach: []Route{
			{
				Prefix:           netip.MustParsePrefix("203.0.113.0/24"),
				OriginASN:        64496,
				ASPath:           []uint32{64501, 64496},
				Communities:      []uint32{64501<<16 | 100},
				LargeCommunities: []LargeCommunity{{GlobalAdmin: 64501, LocalData1: 1, LocalData2: 2}},
			},
		},
	})

	route, ok := tab.Lookup(netip.MustParseAddr("203.0.113.7"))
	if !ok {
		t.Fatal("Lookup should find prefix")
	}

	route.ASPath[0] = 1
	route.Communities[0] = 2
	route.LargeCommunities[0] = LargeCommunity{GlobalAdmin: 3, LocalData1: 4, LocalData2: 5}

	again, ok := tab.Lookup(netip.MustParseAddr("203.0.113.7"))
	if !ok {
		t.Fatal("Lookup should find prefix")
	}
	if again.ASPath[0] != 64501 {
		t.Fatalf("ASPath[0] = %d, want 64501", again.ASPath[0])
	}
	if again.Communities[0] != 64501<<16|100 {
		t.Fatalf("Communities[0] = %d, want %d", again.Communities[0], 64501<<16|100)
	}
	if got := again.LargeCommunities[0]; got != (LargeCommunity{GlobalAdmin: 64501, LocalData1: 1, LocalData2: 2}) {
		t.Fatalf("LargeCommunity = %+v, want {GlobalAdmin:64501 LocalData1:1 LocalData2:2}", got)
	}
}

func TestUpdateFromBMPRouteMonitoring(t *testing.T) {
	msg := mustBMPMessage(t, "203.0.113.0/24", 65002)

	update, ok := updateFromBMP(msg)
	if !ok {
		t.Fatal("updateFromBMP should accept route-monitoring message")
	}
	if len(update.Reach) != 1 {
		t.Fatalf("reach len = %d, want 1", len(update.Reach))
	}
	if len(update.Withdraw) != 0 {
		t.Fatalf("withdraw len = %d, want 0", len(update.Withdraw))
	}

	route := update.Reach[0]
	if route.Prefix != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("prefix = %s, want 203.0.113.0/24", route.Prefix)
	}
	if route.OriginASN != 65002 {
		t.Fatalf("OriginASN = %d, want 65002", route.OriginASN)
	}
	if !route.PostPolicy {
		t.Fatal("PostPolicy = false, want true")
	}
	if route.PeerAddress != netip.MustParseAddr("192.0.2.2") {
		t.Fatalf("PeerAddress = %s, want 192.0.2.2", route.PeerAddress)
	}
}

func TestHandleConnAppliesBMPRouteMonitoring(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	s := &Server{
		table: NewTable(),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleConn(serverConn)
	}()

	wire := mustBMPWire(t, "198.51.100.0/24", 65003)
	if _, err := clientConn.Write(wire); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := clientConn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	<-done

	route, ok := s.Lookup(netip.MustParseAddr("198.51.100.7"))
	if !ok {
		t.Fatal("Lookup should find BMP-learned prefix")
	}
	if route.OriginASN != 65003 {
		t.Fatalf("OriginASN = %d, want 65003", route.OriginASN)
	}
}

func TestServerCloseReturnsWithIdleConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	s := &Server{
		listener: ln,
		table:    NewTable(),
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	s.wg.Add(1)
	go s.accept()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientConn.Close()

	time.Sleep(20 * time.Millisecond)

	done := make(chan error, 1)
	go func() {
		done <- s.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		_ = clientConn.Close()
		t.Fatal("Close blocked with an idle BMP connection")
	}
}

func TestUpdateFromBMPRouteMetadata(t *testing.T) {
	update := bgp.NewBGPUpdateMessage(
		nil,
		[]bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65010, 65020}),
			}),
			bgp.NewPathAttributeCommunities([]uint32{65010<<16 | 100}),
			bgp.NewPathAttributeLargeCommunities([]*bgp.LargeCommunity{
				bgp.NewLargeCommunity(65010, 1, 100),
			}),
			bgp.NewPathAttributeNextHop("192.0.2.1"),
		},
		[]*bgp.IPAddrPrefix{
			bgp.NewIPAddrPrefix(24, "203.0.113.0"),
		},
	)
	peer := bmp.NewBMPPeerHeader(
		bmp.BMP_PEER_TYPE_LOCAL_RIB,
		bmp.BMP_PEER_FLAG_POST_POLICY,
		0,
		"192.0.2.2",
		65010,
		"192.0.2.2",
		0,
	)

	out, ok := updateFromBMP(bmp.NewBMPRouteMonitoring(*peer, update))
	if !ok {
		t.Fatal("updateFromBMP should accept route-monitoring message")
	}
	if len(out.Reach) != 1 {
		t.Fatalf("reach len = %d, want 1", len(out.Reach))
	}

	route := out.Reach[0]
	if got, want := route.ASPath, []uint32{65010, 65020}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ASPath = %v, want %v", got, want)
	}
	if got, want := route.Communities, []uint32{65010<<16 | 100}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("Communities = %v, want %v", got, want)
	}
	if len(route.LargeCommunities) != 1 {
		t.Fatalf("LargeCommunities len = %d, want 1", len(route.LargeCommunities))
	}
	if got := route.LargeCommunities[0]; got != (LargeCommunity{GlobalAdmin: 65010, LocalData1: 1, LocalData2: 100}) {
		t.Fatalf("LargeCommunity = %+v, want {GlobalAdmin:65010 LocalData1:1 LocalData2:100}", got)
	}
}

func TestPrefixFromLabeledVPNNLRI(t *testing.T) {
	nlri := bgp.NewLabeledVPNIPAddrPrefix(
		24,
		"203.0.113.0",
		*bgp.NewMPLSLabelStack(100),
		bgp.NewRouteDistinguisherTwoOctetAS(65000, 1),
	)

	prefix, ok := prefixFromNLRI(nlri)
	if !ok {
		t.Fatal("prefixFromNLRI should decode labeled VPN prefix")
	}
	if prefix != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("prefix = %s, want 203.0.113.0/24", prefix)
	}
}

func mustBMPWire(t *testing.T, prefix string, origin uint32) []byte {
	t.Helper()

	wire, err := mustBMPMessage(t, prefix, origin).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return wire
}

func mustBMPMessage(t *testing.T, prefix string, origin uint32) *bmp.BMPMessage {
	t.Helper()

	nlri := bgp.NewIPAddrPrefix(prefixBits(t, prefix), prefixAddr(t, prefix))
	update := bgp.NewBGPUpdateMessage(
		nil,
		[]bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{uint16(origin)}),
			}),
			bgp.NewPathAttributeNextHop("192.0.2.1"),
		},
		[]*bgp.IPAddrPrefix{nlri},
	)

	peer := bmp.NewBMPPeerHeader(
		bmp.BMP_PEER_TYPE_LOCAL_RIB,
		bmp.BMP_PEER_FLAG_POST_POLICY,
		0,
		"192.0.2.2",
		origin,
		"192.0.2.2",
		0,
	)

	return bmp.NewBMPRouteMonitoring(*peer, update)
}

func prefixBits(t *testing.T, prefix string) uint8 {
	t.Helper()

	pfx := netip.MustParsePrefix(prefix)
	return uint8(pfx.Bits())
}

func prefixAddr(t *testing.T, prefix string) string {
	t.Helper()

	pfx := netip.MustParsePrefix(prefix)
	return pfx.Addr().String()
}
