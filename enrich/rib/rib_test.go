package rib

import (
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
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

func TestTableEnrichSkipsDefaultRoute(t *testing.T) {
	tab := NewTable()
	tab.Apply(Update{
		Reach: []Route{
			{Prefix: netip.MustParsePrefix("0.0.0.0/0"), OriginASN: 64500, ASPath: []uint32{64500}},
			{Prefix: netip.MustParsePrefix("::/0"), OriginASN: 64501, ASPath: []uint32{64501}},
			{Prefix: netip.MustParsePrefix("203.0.113.0/24"), OriginASN: 64496, ASPath: []uint32{64500, 64496}},
		},
	})

	// the default route says which upstream carries the traffic, not who
	// owns the address, so it leaves the label to the next backend
	src, dst := tab.Enrich(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:db8::1"))
	if src.ASN != 0 || dst.ASN != 0 {
		t.Fatalf("labels from default routes = %d and %d, want 0 and 0", src.ASN, dst.ASN)
	}

	// a more specific route still labels
	if _, dst := tab.Enrich(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("203.0.113.7")); dst.ASN != 64496 {
		t.Fatalf("dst ASN = %d, want 64496", dst.ASN)
	}

	// the default route stays visible to a lookup
	route, ok := tab.Lookup(netip.MustParseAddr("8.8.8.8"))
	if !ok || route.OriginASN != 64500 || route.Prefix != netip.MustParsePrefix("0.0.0.0/0") {
		t.Fatalf("Lookup = %+v ok=%v, want the default route from 64500", route, ok)
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

	// the route is served while the session is up
	deadline := time.Now().Add(2 * time.Second)
	for {
		route, ok := s.Lookup(netip.MustParseAddr("198.51.100.7"))
		if ok {
			if route.OriginASN != 65003 {
				t.Fatalf("OriginASN = %d, want 65003", route.OriginASN)
			}
			if route.PeerAddress != netip.MustParseAddr("192.0.2.2") {
				t.Fatalf("PeerAddress = %s, want 192.0.2.2", route.PeerAddress)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Lookup should find BMP-learned prefix while the session is up")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// the end of the session keeps the routes, the next session replaces
	// them peer by peer as it announces them again
	if err := clientConn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	<-done

	if _, ok := s.Lookup(netip.MustParseAddr("198.51.100.7")); !ok {
		t.Fatal("route did not survive the end of its BMP session")
	}
}

func TestHandleConnPeerUpReplacesPeer(t *testing.T) {
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

	if _, err := clientConn.Write(mustBMPWire(t, "198.51.100.0/24", 65003)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	waitForRoute(t, s, "198.51.100.7", true)

	// a peer up for the same peer means a fresh dump follows, so what the
	// earlier session announced for it goes away
	peer := bmp.NewBMPPeerHeader(
		bmp.BMP_PEER_TYPE_LOCAL_RIB,
		bmp.BMP_PEER_FLAG_POST_POLICY,
		0,
		"192.0.2.2",
		65003,
		"192.0.2.2",
		0,
	)
	open := bgp.NewBGPOpenMessage(65003, 90, "192.0.2.2", nil)
	up, err := bmp.NewBMPPeerUpNotification(*peer, "192.0.2.1", 179, 40000, open, open).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if _, err := clientConn.Write(up); err != nil {
		t.Fatalf("Write: %v", err)
	}
	waitForRoute(t, s, "198.51.100.7", false)

	// the dump after the peer up lands again
	if _, err := clientConn.Write(mustBMPWire(t, "203.0.113.0/24", 65003)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	waitForRoute(t, s, "203.0.113.7", true)

	_ = clientConn.Close()
	<-done
}

// waitForRoute polls the server until addr is present or absent
func waitForRoute(t *testing.T, s *Server, addr string, present bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, ok := s.Lookup(netip.MustParseAddr(addr))
		if ok == present {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("route %s present=%v, want present=%v", addr, ok, present)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHandleConnPeerDownWithdrawsPeer(t *testing.T) {
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

	if _, err := clientConn.Write(mustBMPWire(t, "198.51.100.0/24", 65003)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := s.Lookup(netip.MustParseAddr("198.51.100.7")); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("route never arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}

	peer := bmp.NewBMPPeerHeader(
		bmp.BMP_PEER_TYPE_LOCAL_RIB,
		bmp.BMP_PEER_FLAG_POST_POLICY,
		0,
		"192.0.2.2",
		65003,
		"192.0.2.2",
		0,
	)
	down, err := bmp.NewBMPPeerDownNotification(*peer, bmp.BMP_PEER_DOWN_REASON_PEER_DE_CONFIGURED, nil, nil).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if _, err := clientConn.Write(down); err != nil {
		t.Fatalf("Write: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for {
		if _, ok := s.Lookup(netip.MustParseAddr("198.51.100.7")); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("route survived the peer down notification")
		}
		time.Sleep(5 * time.Millisecond)
	}

	_ = clientConn.Close()
	<-done
}

func TestHandleConnPeerNotificationsIgnorePolicy(t *testing.T) {
	s := &Server{table: NewTable()}
	client, done := startSession(t, s)

	// BIRD sends peer up and peer down with the L flag clear whatever the
	// monitoring policy, so they must reach the post policy routes too
	write(t, client, mustBMPWire(t, "198.51.100.0/24", 65003))
	write(t, client, mustBMPWireFrom(t, "203.0.113.0/24", 65004, "192.0.2.4", 0))
	waitForRoute(t, s, "198.51.100.7", true)
	waitForRoute(t, s, "203.0.113.7", true)

	write(t, client, mustPeerDownWire(t, "192.0.2.2", 0))
	waitForRoute(t, s, "198.51.100.7", false)
	if _, ok := s.Lookup(netip.MustParseAddr("203.0.113.7")); !ok {
		t.Fatal("peer down for 192.0.2.2 removed the routes of 192.0.2.4")
	}

	write(t, client, mustBMPWire(t, "198.51.100.0/24", 65003))
	waitForRoute(t, s, "198.51.100.7", true)
	write(t, client, mustPeerUpWire(t, "192.0.2.2", 0))
	waitForRoute(t, s, "198.51.100.7", false)

	_ = client.Close()
	<-done
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

func TestHandleConnEndsOnBadHeader(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header []byte
	}{
		{"zero", []byte{3, 0, 0, 0, 0, 0}},
		{"below header", []byte{3, 0, 0, 0, 5, 0}},
		{"above cap", []byte{3, 0xff, 0xff, 0xff, 0xff, 0}},
		// versions 1 and 2 belong to the drafts before RFC 7854
		{"version 2", []byte{2, 0, 0, 0, 6, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer clientConn.Close()

			s := &Server{table: NewTable()}
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.handleConn(serverConn)
			}()

			if _, err := clientConn.Write(tc.header); err != nil {
				t.Fatalf("Write: %v", err)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("session did not end on a header no bmp version 3 message can have")
			}
		})
	}
}

func TestServerCloseReturnsAfterZeroLengthHeader(t *testing.T) {
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
	if _, err := clientConn.Write([]byte{3, 0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("Write: %v", err)
	}
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
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind a session that read a zero length header")
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

func TestPrefixFromNLRI(t *testing.T) {
	vpn := func(rd uint32) bgp.AddrPrefixInterface {
		return bgp.NewLabeledVPNIPAddrPrefix(
			24,
			"203.0.113.0",
			*bgp.NewMPLSLabelStack(100),
			bgp.NewRouteDistinguisherTwoOctetAS(65000, rd),
		)
	}

	for _, tc := range []struct {
		name string
		nlri bgp.AddrPrefixInterface
		want netip.Prefix
		ok   bool
	}{
		{"ipv4", bgp.NewIPAddrPrefix(24, "203.0.113.0"), netip.MustParsePrefix("203.0.113.0/24"), true},
		{"ipv6", bgp.NewIPv6AddrPrefix(32, "2001:db8::"), netip.MustParsePrefix("2001:db8::/32"), true},
		// an ipv4 mapped ipv6 prefix stays an ipv6 prefix, unmapping it
		// would give an ipv4 address 96 bits of prefix
		{"mapped", bgp.NewIPv6AddrPrefix(96, "::ffff:0.0.0.0"), netip.MustParsePrefix("::ffff:0.0.0.0/96"), true},
		// a VPN route belongs to a VRF and not to the global table, and
		// without the route distinguisher two VRFs would overwrite each other
		{"vpn", vpn(1), netip.Prefix{}, false},
		{"labeled unicast", bgp.NewLabeledIPAddrPrefix(24, "203.0.113.0", *bgp.NewMPLSLabelStack(100)), netip.Prefix{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := prefixFromNLRI(tc.nlri)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("prefixFromNLRI = %s ok=%v, want %s ok=%v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestUpdateFromBMPSkipsVPNRoutes(t *testing.T) {
	update := bgp.NewBGPUpdateMessage(
		nil,
		[]bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65010}),
			}),
			bgp.NewPathAttributeMpReachNLRI("192.0.2.1", []bgp.AddrPrefixInterface{
				bgp.NewLabeledVPNIPAddrPrefix(24, "10.0.0.0", *bgp.NewMPLSLabelStack(100), bgp.NewRouteDistinguisherTwoOctetAS(65000, 1)),
			}),
		},
		nil,
	)
	peer := bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_GLOBAL, 0, 0, "192.0.2.2", 65010, "192.0.2.2", 0)

	out, ok := updateFromBMP(bmp.NewBMPRouteMonitoring(*peer, update))
	if !ok {
		t.Fatal("updateFromBMP should accept route-monitoring message")
	}
	if len(out.Reach) != 0 {
		t.Fatalf("reach = %+v, want no global routes from a VPN update", out.Reach)
	}
}

func TestUpdateFromBMPSkipsMulticastRoutes(t *testing.T) {
	v4 := bgp.NewIPAddrPrefix(24, "203.0.113.0")
	v6 := bgp.NewIPv6AddrPrefix(32, "2001:db8::")

	for _, tc := range []struct {
		name     string
		nlri     bgp.AddrPrefixInterface
		nexthop  string
		safi     uint8
		withdraw bool
		want     int
	}{
		{"ipv4 unicast reach", v4, "192.0.2.1", bgp.SAFI_UNICAST, false, 1},
		{"ipv6 unicast reach", v6, "2001:db8::1", bgp.SAFI_UNICAST, false, 1},
		{"ipv4 unicast withdraw", v4, "", bgp.SAFI_UNICAST, true, 1},
		// a multicast route shares the prefix and the path id of the
		// unicast route, which it would replace or withdraw
		{"ipv4 multicast reach", v4, "192.0.2.1", bgp.SAFI_MULTICAST, false, 0},
		{"ipv6 multicast reach", v6, "2001:db8::1", bgp.SAFI_MULTICAST, false, 0},
		{"ipv4 multicast withdraw", v4, "", bgp.SAFI_MULTICAST, true, 0},
		{"ipv6 multicast withdraw", v6, "", bgp.SAFI_MULTICAST, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attrs []bgp.PathAttributeInterface
			if tc.withdraw {
				unreach := bgp.NewPathAttributeMpUnreachNLRI([]bgp.AddrPrefixInterface{tc.nlri})
				unreach.SAFI = tc.safi
				attrs = []bgp.PathAttributeInterface{unreach}
			} else {
				reach := bgp.NewPathAttributeMpReachNLRI(tc.nexthop, []bgp.AddrPrefixInterface{tc.nlri})
				reach.SAFI = tc.safi
				attrs = []bgp.PathAttributeInterface{
					bgp.NewPathAttributeOrigin(0),
					bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
						bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65010}),
					}),
					reach,
				}
			}
			peer := bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_GLOBAL, 0, 0, "192.0.2.2", 65010, "192.0.2.2", 0)

			// through the wire so gobgp decodes the NLRI by the family the
			// attribute names
			wire, err := bmp.NewBMPRouteMonitoring(*peer, bgp.NewBGPUpdateMessage(nil, attrs, nil)).Serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			msg, err := bmp.ParseBMPMessage(wire)
			if err != nil {
				t.Fatalf("ParseBMPMessage: %v", err)
			}

			out, ok := updateFromBMP(msg)
			if !ok {
				t.Fatal("updateFromBMP should accept route-monitoring message")
			}
			if got := len(out.Reach) + len(out.Withdraw); got != tc.want {
				t.Fatalf("reach %+v withdraw %+v, want %d routes", out.Reach, out.Withdraw, tc.want)
			}
		})
	}
}

func TestTableCountsMappedPrefixAsIPv6(t *testing.T) {
	tab := NewTable()
	prefix, ok := prefixFromNLRI(bgp.NewIPv6AddrPrefix(96, "::ffff:0.0.0.0"))
	if !ok {
		t.Fatal("prefixFromNLRI rejected an ipv4 mapped ipv6 prefix")
	}
	tab.Apply(Update{Reach: []Route{{Prefix: prefix, OriginASN: 64500}}})

	if got := tab.Summary(); got != (Summary{PrefixesV6: 1, Routes: 1, Peers: 1}) {
		t.Fatalf("summary = %+v, want one ipv6 prefix", got)
	}
}

// startSession runs handleConn on one end of a pipe and returns the other
// end with a channel that closes when the session ends
func startSession(t *testing.T, s *Server) (net.Conn, chan struct{}) {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleConn(serverConn)
	}()
	return clientConn, done
}

func write(t *testing.T, conn net.Conn, wire []byte) {
	t.Helper()

	if _, err := conn.Write(wire); err != nil {
		t.Fatalf("Write: %v", err)
	}
}

func mustPeerUpWire(t *testing.T, addr string, flags uint8) []byte {
	t.Helper()

	peer := bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_GLOBAL, flags, 0, addr, 65003, addr, 0)
	open := bgp.NewBGPOpenMessage(65003, 90, addr, nil)
	wire, err := bmp.NewBMPPeerUpNotification(*peer, "192.0.2.1", 179, 40000, open, open).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return wire
}

func mustPeerDownWire(t *testing.T, addr string, flags uint8) []byte {
	t.Helper()

	peer := bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_GLOBAL, flags, 0, addr, 65003, addr, 0)
	wire, err := bmp.NewBMPPeerDownNotification(*peer, bmp.BMP_PEER_DOWN_REASON_PEER_DE_CONFIGURED, nil, nil).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return wire
}

func mustBMPWire(t *testing.T, prefix string, origin uint32) []byte {
	t.Helper()

	return mustBMPWireFrom(t, prefix, origin, "192.0.2.2", bmp.BMP_PEER_FLAG_POST_POLICY)
}

// mustBMPWireFrom serializes a route monitoring message for prefix from the
// peer at addr with the given per peer header flags
func mustBMPWireFrom(t *testing.T, prefix string, origin uint32, addr string, flags uint8) []byte {
	t.Helper()

	msg := mustBMPMessage(t, prefix, origin)
	msg.PeerHeader = *bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_LOCAL_RIB, flags, 0, addr, origin, addr, 0)
	wire, err := msg.Serialize()
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

func TestTableKeepsRoutesPerPeer(t *testing.T) {
	tab := NewTable()
	pfx := netip.MustParsePrefix("203.0.113.0/24")
	a := Peer{Address: netip.MustParseAddr("192.0.2.1")}
	b := Peer{Address: netip.MustParseAddr("192.0.2.2")}

	tab.Apply(Update{Reach: []Route{
		{Prefix: pfx, OriginASN: 64501, PeerASN: 64501, PeerAddress: a.Address},
		{Prefix: pfx, OriginASN: 64502, PeerASN: 64502, PeerAddress: b.Address},
	}})

	if got := tab.Summary(); got.Routes != 2 || got.PrefixesV4 != 1 || got.Peers != 2 {
		t.Fatalf("summary = %+v, want 2 routes, 1 prefix, 2 peers", got)
	}

	// the lowest peer address wins while both are pre policy
	route, ok := tab.Lookup(netip.MustParseAddr("203.0.113.9"))
	if !ok || route.OriginASN != 64501 {
		t.Fatalf("best route = %+v, want origin 64501 from the lower peer", route)
	}

	// a withdraw from one peer leaves the other peer's route in place
	tab.Apply(Update{Peer: a, Withdraw: []netip.Prefix{pfx}})
	route, ok = tab.Lookup(netip.MustParseAddr("203.0.113.9"))
	if !ok || route.OriginASN != 64502 {
		t.Fatalf("route after withdraw = %+v ok=%v, want origin 64502 from the other peer", route, ok)
	}
	if got := tab.Summary(); got.Routes != 1 || got.Peers != 1 {
		t.Fatalf("summary after withdraw = %+v, want 1 route from 1 peer", got)
	}

	tab.Apply(Update{Peer: b, Withdraw: []netip.Prefix{pfx}})
	if _, ok := tab.Lookup(netip.MustParseAddr("203.0.113.9")); ok {
		t.Fatal("prefix still present after every peer withdrew it")
	}
	if got := tab.Summary(); got.Routes != 0 || got.PrefixesV4 != 0 || got.Peers != 0 {
		t.Fatalf("summary after full withdraw = %+v, want empty", got)
	}
}

func TestTableCountsInconsistencies(t *testing.T) {
	tab := NewTable()
	peer := Peer{Address: netip.MustParseAddr("192.0.2.1")}
	lost := netip.MustParsePrefix("203.0.113.0/24")
	bare := netip.MustParsePrefix("198.51.100.0/24")
	orphan := netip.MustParsePrefix("192.0.2.0/24")
	for i, prefix := range []netip.Prefix{lost, bare, orphan} {
		origin := uint32(64501 + i)
		tab.Apply(Update{Reach: []Route{{Prefix: prefix, OriginASN: origin, ASPath: []uint32{origin}, PeerAddress: peer.Address}}})
	}

	// a route without a prefix is a bug of the caller and stays out
	tab.Apply(Update{Reach: []Route{{OriginASN: 64500, PeerAddress: peer.Address}}})

	// best credits the view with a prefix it lost, a route refers to
	// metadata the table released, and the view gives up a prefix best lost
	v := tab.views[peer]
	v.routes.Delete(lost)
	value, _ := v.routes.Get(bare)
	delete(tab.metas, value.metaID)
	tab.best.Delete(orphan)

	for _, addr := range []string{"203.0.113.7", "198.51.100.7"} {
		if route, ok := tab.Lookup(netip.MustParseAddr(addr)); ok {
			t.Fatalf("Lookup(%s) = %+v, want no route from a table that contradicts itself", addr, route)
		}
	}
	tab.RemovePeer(peer)
	if got := tab.faults.Load(); got != 4 {
		t.Fatalf("faults = %d, want 4", got)
	}
}

// fillTable announces n consecutive /24 prefixes from 1.0.0.0 by peer, with
// a thousand distinct AS paths between them
func fillTable(tab *Table, peer netip.Addr, n int) {
	batch := make([]Route, 0, 1024)
	for i := range n {
		addr := netip.AddrFrom4([4]byte{byte(1 + i>>16), byte(i >> 8), byte(i), 0})
		origin := uint32(64500 + i%1000)
		batch = append(batch, Route{
			Prefix:      netip.PrefixFrom(addr, 24),
			OriginASN:   origin,
			ASPath:      []uint32{64496, origin},
			PeerASN:     64496,
			PeerAddress: peer,
		})
		if len(batch) == cap(batch) || i == n-1 {
			tab.Apply(Update{Reach: batch})
			batch = batch[:0]
		}
	}
}

func TestTableHeapPerPrefix(t *testing.T) {
	const n = 1 << 17

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	tab := NewTable()
	fillTable(tab, netip.MustParseAddr("192.0.2.1"), n)

	runtime.GC()
	runtime.ReadMemStats(&after)
	if got := tab.Summary(); got.PrefixesV4 != n || got.Routes != n {
		t.Fatalf("summary = %+v, want %d prefixes and routes", got, n)
	}
	runtime.KeepAlive(tab)

	// a full table is about 1.25M prefixes, at the 983 bytes a prefix took
	// with a map per prefix that is 1.2 GB on a 2 GB router
	perPrefix := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / n
	t.Logf("heap per prefix: %d bytes", perPrefix)
	if perPrefix > 256 {
		t.Fatalf("heap per prefix = %d bytes, want at most 256", perPrefix)
	}
}

// ribModel is the obvious RIB the table must agree with, every route per
// view and a linear best path search
type ribModel map[Peer]map[netip.Prefix]uint32

func (m ribModel) best(prefix netip.Prefix) (Peer, uint32, bool) {
	var best Peer
	var origin uint32
	found := false
	for peer, routes := range m {
		if o, ok := routes[prefix]; ok && (!found || betterPeer(peer, best)) {
			best, origin, found = peer, o, true
		}
	}
	return best, origin, found
}

func (m ribModel) lookup(addr netip.Addr) (netip.Prefix, Peer, uint32, bool) {
	for bits := addr.BitLen(); bits >= 0; bits-- {
		prefix, _ := addr.Prefix(bits)
		if peer, origin, ok := m.best(prefix); ok {
			return prefix, peer, origin, true
		}
	}
	return netip.Prefix{}, Peer{}, 0, false
}

func (m ribModel) check(t *testing.T, tab *Table, probes []netip.Addr, step int) {
	t.Helper()

	var want Summary
	prefixes := make(map[netip.Prefix]struct{})
	metas := make(map[[2]any]struct{})
	for peer, routes := range m {
		if len(routes) > 0 {
			want.Peers++
		}
		for prefix, origin := range routes {
			want.Routes++
			prefixes[prefix] = struct{}{}
			metas[[2]any{peer, origin}] = struct{}{}
		}
	}
	for prefix := range prefixes {
		if prefix.Addr().Is4() {
			want.PrefixesV4++
		} else {
			want.PrefixesV6++
		}
	}
	if got := tab.Summary(); got != want {
		t.Fatalf("step %d: summary = %+v, want %+v", step, got, want)
	}
	if got := len(tab.metas); got != len(metas) {
		t.Fatalf("step %d: metadata entries = %d, want %d", step, got, len(metas))
	}

	for _, addr := range probes {
		prefix, peer, origin, ok := m.lookup(addr)
		route, gotOK := tab.Lookup(addr)
		if gotOK != ok || route.Prefix != prefix || route.OriginASN != origin || route.Peer() != peer {
			t.Fatalf("step %d: Lookup(%s) = %s origin %d from %+v ok=%v, want %s origin %d from %+v ok=%v",
				step, addr, route.Prefix, route.OriginASN, route.Peer(), gotOK, prefix, origin, peer, ok)
		}
		if prefix.Bits() == 0 {
			origin = 0
		}
		if labels, _ := tab.Enrich(addr, addr); labels.ASN != origin {
			t.Fatalf("step %d: label for %s = %d, want %d", step, addr, labels.ASN, origin)
		}
	}
}

func TestTableMatchesModel(t *testing.T) {
	peers := []Peer{
		{Address: netip.MustParseAddr("192.0.2.1")},
		{Address: netip.MustParseAddr("192.0.2.1"), PostPolicy: true},
		{Address: netip.MustParseAddr("192.0.2.2")},
		{Address: netip.MustParseAddr("192.0.2.2"), Distinguisher: 5},
		{Address: netip.MustParseAddr("2001:db8::2"), PostPolicy: true},
	}
	var prefixes []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25", "10.1.3.0/24",
		"::/0", "2001:db8::/32", "2001:db8:1::/48",
	} {
		prefixes = append(prefixes, netip.MustParsePrefix(s))
	}
	var probes []netip.Addr
	for _, s := range []string{
		"10.1.2.200", "10.1.2.1", "10.1.3.1", "10.2.0.1", "11.0.0.1",
		"2001:db8:1::1", "2001:db8:2::1", "2001:db9::1",
	} {
		probes = append(probes, netip.MustParseAddr(s))
	}

	rng := rand.New(rand.NewPCG(1, 2))
	tab := NewTable()
	model := make(ribModel)
	for step := range 4000 {
		peer := peers[rng.IntN(len(peers))]
		prefix := prefixes[rng.IntN(len(prefixes))]
		switch op := rng.IntN(10); {
		case op < 5:
			origin := uint32(64500 + rng.IntN(4))
			tab.Apply(Update{Reach: []Route{{
				Prefix:            prefix,
				OriginASN:         origin,
				ASPath:            []uint32{origin},
				PeerAddress:       peer.Address,
				PeerDistinguisher: peer.Distinguisher,
				PostPolicy:        peer.PostPolicy,
			}}})
			if model[peer] == nil {
				model[peer] = make(map[netip.Prefix]uint32)
			}
			model[peer][prefix] = origin
		case op < 8:
			tab.Apply(Update{Peer: peer, Withdraw: []netip.Prefix{prefix}})
			delete(model[peer], prefix)
		case op < 9:
			tab.Apply(Update{Withdraw: []netip.Prefix{prefix}})
			for _, routes := range model {
				delete(routes, prefix)
			}
		default:
			tab.RemovePeer(peer)
			delete(model, peer)
		}
		model.check(t, tab, probes, step)
		checkInvariants(t, tab)
	}
}

// checkInvariants verifies that best, the views and the counters agree
func checkInvariants(t *testing.T, tab *Table) {
	t.Helper()

	tab.mu.RLock()
	defer tab.mu.RUnlock()

	if n := tab.faults.Load(); n != 0 {
		t.Fatalf("the table counted %d faults", n)
	}

	routes := 0
	for peer, v := range tab.views {
		if v.peer != peer || v.routes.Size() == 0 {
			t.Fatalf("view %+v under key %+v holds %d routes", v.peer, peer, v.routes.Size())
		}
		routes += v.routes.Size()
		for prefix := range v.routes.All() {
			if _, ok := tab.best.Get(prefix); !ok {
				t.Fatalf("%s of %+v is missing from best", prefix, v.peer)
			}
		}
	}
	if routes != tab.routes {
		t.Fatalf("route counter = %d, views hold %d", tab.routes, routes)
	}
	byPreference := func(a, b *view) int {
		switch {
		case betterPeer(a.peer, b.peer):
			return -1
		case betterPeer(b.peer, a.peer):
			return 1
		}
		return 0
	}
	if len(tab.order) != len(tab.views) || !slices.IsSortedFunc(tab.order, byPreference) {
		t.Fatalf("order holds %d views out of preference, the table %d", len(tab.order), len(tab.views))
	}

	for prefix, best := range tab.best.All() {
		var holders uint32
		var first *view
		var value viewRoute
		for _, v := range tab.order {
			if r, ok := v.routes.Get(prefix); ok {
				if holders++; first == nil {
					first, value = v, r
				}
			}
		}
		if best.views != holders || best.view != first || int(best.bits) != prefix.Bits() ||
			best.originASN != value.originASN || best.originASSet != value.originASSet {
			t.Fatalf("best for %s = %+v, want the route of %+v and %d views", prefix, best, first, holders)
		}
	}
}

func TestRemovePeerWithConcurrentWriter(t *testing.T) {
	tab := NewTable()
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	fillTable(tab, a, 1<<14)
	fillTable(tab, b, 1<<12)

	// b churns the prefixes it shares with a while a goes away in chunks
	var wg sync.WaitGroup
	wg.Go(func() { tab.RemovePeer(Peer{Address: a}) })
	wg.Go(func() {
		for i := range 1 << 12 {
			prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{1, byte(i >> 8), byte(i), 0}), 24)
			tab.Apply(Update{Peer: Peer{Address: b}, Withdraw: []netip.Prefix{prefix}})
			tab.Apply(Update{Reach: []Route{{Prefix: prefix, OriginASN: 64999, PeerAddress: b}}})
		}
	})
	wg.Wait()

	checkInvariants(t, tab)
	if got := tab.Summary(); got != (Summary{PrefixesV4: 1 << 12, Routes: 1 << 12, Peers: 1}) {
		t.Fatalf("summary = %+v, want only the routes of %s", got, b)
	}
	if route, ok := tab.Lookup(netip.MustParseAddr("1.0.0.1")); !ok || route.OriginASN != 64999 {
		t.Fatalf("Lookup = %+v ok=%v, want origin 64999 from %s", route, ok, b)
	}
}

func TestConcurrentRemovals(t *testing.T) {
	const n = 1 << 13

	for range 5 {
		tab := NewTable()
		a := netip.MustParseAddr("192.0.2.1")
		b := netip.MustParseAddr("192.0.2.2")
		c := netip.MustParseAddr("192.0.2.3")
		fillTable(tab, a, n)
		fillTable(tab, b, n)

		// a, the preferred view, goes while b is taken apart, and c
		// announces the prefixes again from the end, so it reaches prefixes
		// that the removal of b has not withdrawn yet
		var wg sync.WaitGroup
		wg.Go(func() { tab.RemovePeer(Peer{Address: b}) })
		wg.Go(func() {
			tab.RemovePeer(Peer{Address: a})
			for i := n - 1; i >= 0; i-- {
				prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + i>>16), byte(i >> 8), byte(i), 0}), 24)
				tab.Apply(Update{Reach: []Route{{Prefix: prefix, OriginASN: 64999, PeerAddress: c}}})
			}
		})
		wg.Wait()

		checkInvariants(t, tab)
		if got := tab.Summary(); got != (Summary{PrefixesV4: n, Routes: n, Peers: 1}) {
			t.Fatalf("summary = %+v, want only the routes of %s", got, c)
		}
	}
}

func TestRemovePeerLetsLookupsThrough(t *testing.T) {
	const n = 1 << 17

	tab := NewTable()
	big := netip.MustParseAddr("192.0.2.1")
	fillTable(tab, big, n)
	probe := netip.MustParseAddr("1.0.0.1")

	// the collector enriches under its own write lock, a lookup that waits
	// for the whole removal stalls ingestion for as long
	running := make(chan struct{})
	stop := make(chan struct{})
	longest := make(chan time.Duration)
	go func() {
		var worst time.Duration
		for i := 0; ; i++ {
			start := time.Now()
			tab.Enrich(probe, probe)
			worst = max(worst, time.Since(start))
			if i == 0 {
				close(running)
			}
			select {
			case <-stop:
				longest <- worst
				return
			default:
			}
		}
	}()
	<-running

	start := time.Now()
	tab.RemovePeer(Peer{Address: big})
	total := time.Since(start)
	close(stop)
	worst := <-longest

	if got := tab.Summary(); got != (Summary{}) {
		t.Fatalf("summary after RemovePeer = %+v, want empty", got)
	}
	t.Logf("removal took %v, the longest lookup %v", total, worst)
	if worst > total/2 {
		t.Fatalf("a lookup waited %v of the %v removal", worst, total)
	}
}

func TestTablePrefersPostPolicy(t *testing.T) {
	tab := NewTable()
	pfx := netip.MustParsePrefix("2001:db8::/32")
	addr := netip.MustParseAddr("192.0.2.1")

	tab.Apply(Update{Reach: []Route{
		{Prefix: pfx, OriginASN: 64511, PeerAddress: addr, PostPolicy: false},
		{Prefix: pfx, OriginASN: 64512, PeerAddress: addr, PostPolicy: true},
	}})

	route, ok := tab.Lookup(netip.MustParseAddr("2001:db8::1"))
	if !ok || route.OriginASN != 64512 || !route.PostPolicy {
		t.Fatalf("best route = %+v, want the post policy view", route)
	}

	// dropping the post policy view falls back to the pre policy one
	tab.RemovePeer(Peer{Address: addr, PostPolicy: true})
	route, ok = tab.Lookup(netip.MustParseAddr("2001:db8::1"))
	if !ok || route.OriginASN != 64511 {
		t.Fatalf("route after removing the post policy peer = %+v, want origin 64511", route)
	}
}

func TestRemovePeerDropsOnlyThatPeer(t *testing.T) {
	tab := NewTable()
	a := Peer{Address: netip.MustParseAddr("192.0.2.1")}
	b := Peer{Address: netip.MustParseAddr("192.0.2.2")}

	tab.Apply(Update{Reach: []Route{
		{Prefix: netip.MustParsePrefix("203.0.113.0/24"), OriginASN: 1, PeerAddress: a.Address},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), OriginASN: 2, PeerAddress: a.Address},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), OriginASN: 3, PeerAddress: b.Address},
	}})

	tab.RemovePeer(a)

	if _, ok := tab.Lookup(netip.MustParseAddr("203.0.113.1")); ok {
		t.Fatal("prefix announced only by the removed peer is still present")
	}
	route, ok := tab.Lookup(netip.MustParseAddr("198.51.100.1"))
	if !ok || route.OriginASN != 3 {
		t.Fatalf("route from the remaining peer = %+v ok=%v, want origin 3", route, ok)
	}
	if got := tab.Peers(); len(got) != 1 || got[0] != b {
		t.Fatalf("peers = %v, want only %v", got, b)
	}
	if got := len(tab.metas); got != 1 {
		t.Fatalf("metadata entries = %d, want 1", got)
	}
}

func TestRemovePeerViewsKeepsOtherDistinguishers(t *testing.T) {
	tab := NewTable()
	addr := netip.MustParseAddr("192.0.2.1")
	pfx := netip.MustParsePrefix("203.0.113.0/24")

	tab.Apply(Update{Reach: []Route{
		{Prefix: pfx, OriginASN: 1, PeerAddress: addr},
		{Prefix: pfx, OriginASN: 2, PeerAddress: addr, PostPolicy: true},
		{Prefix: pfx, OriginASN: 3, PeerAddress: addr, PeerDistinguisher: 7},
	}})

	tab.RemovePeerViews(Peer{Address: addr, PostPolicy: true})

	route, ok := tab.Lookup(netip.MustParseAddr("203.0.113.1"))
	if !ok || route.OriginASN != 3 {
		t.Fatalf("route = %+v ok=%v, want origin 3 from the other distinguisher", route, ok)
	}
	if got := tab.Peers(); len(got) != 1 || got[0] != (Peer{Address: addr, Distinguisher: 7}) {
		t.Fatalf("peers = %v, want only the view with distinguisher 7", got)
	}
}

func TestUpdateFromBMPMergesAS4Path(t *testing.T) {
	seq := func(asns ...uint16) bgp.AsPathParamInterface {
		return bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns)
	}
	seq4 := func(asns ...uint32) *bgp.As4PathParam {
		return bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns)
	}
	const trans = bgp.AS_TRANS

	for _, tc := range []struct {
		name     string
		flags    uint8
		asPath   []bgp.AsPathParamInterface
		as4Path  []*bgp.As4PathParam
		extra    []bgp.PathAttributeInterface
		wantPath []uint32
		origin   uint32
		asSet    bool
	}{
		{
			name:     "same length",
			flags:    bmp.BMP_PEER_FLAG_TWO_AS,
			asPath:   []bgp.AsPathParamInterface{seq(65010, trans)},
			as4Path:  []*bgp.As4PathParam{seq4(65010, 4200000001)},
			wantPath: []uint32{65010, 4200000001},
			origin:   4200000001,
		},
		{
			name:     "leading asns from as_path",
			flags:    bmp.BMP_PEER_FLAG_TWO_AS,
			asPath:   []bgp.AsPathParamInterface{seq(64500, 65010, trans)},
			as4Path:  []*bgp.As4PathParam{seq4(65010, 4200000001)},
			wantPath: []uint32{64500, 65010, 4200000001},
			origin:   4200000001,
		},
		{
			name:  "set counts as one",
			flags: bmp.BMP_PEER_FLAG_TWO_AS,
			asPath: []bgp.AsPathParamInterface{
				seq(64500, 65010),
				bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{trans, 65020}),
			},
			as4Path: []*bgp.As4PathParam{
				seq4(65010),
				bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint32{4200000002, 65020}),
			},
			wantPath: []uint32{64500, 65010, 4200000002, 65020},
			asSet:    true,
		},
		{
			name:  "leading confederation segment",
			flags: bmp.BMP_PEER_FLAG_TWO_AS,
			asPath: []bgp.AsPathParamInterface{
				bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100}),
				seq(65010, trans),
			},
			as4Path:  []*bgp.As4PathParam{seq4(65010, 4200000001)},
			wantPath: []uint32{65100, 65010, 4200000001},
			origin:   4200000001,
		},
		{
			name:     "as4_path longer than as_path",
			flags:    bmp.BMP_PEER_FLAG_TWO_AS,
			asPath:   []bgp.AsPathParamInterface{seq(trans)},
			as4Path:  []*bgp.As4PathParam{seq4(65010, 4200000001)},
			wantPath: []uint32{trans},
			origin:   trans,
		},
		{
			name:     "four byte session",
			asPath:   []bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65010, trans})},
			as4Path:  []*bgp.As4PathParam{seq4(65010, 4200000001)},
			wantPath: []uint32{65010, trans},
			origin:   trans,
		},
		{
			name:    "aggregator not as_trans",
			flags:   bmp.BMP_PEER_FLAG_TWO_AS,
			asPath:  []bgp.AsPathParamInterface{seq(65010, 65030)},
			as4Path: []*bgp.As4PathParam{seq4(65010, 4200000001)},
			extra: []bgp.PathAttributeInterface{
				bgp.NewPathAttributeAggregator(uint16(65030), "192.0.2.30"),
				bgp.NewPathAttributeAs4Aggregator(4200000001, "192.0.2.30"),
			},
			wantPath: []uint32{65010, 65030},
			origin:   65030,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := []bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(0),
				bgp.NewPathAttributeAsPath(tc.asPath),
				bgp.NewPathAttributeNextHop("192.0.2.1"),
				bgp.NewPathAttributeAs4Path(tc.as4Path),
			}
			update := bgp.NewBGPUpdateMessage(nil, append(attrs, tc.extra...), []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "203.0.113.0")})
			peer := bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_GLOBAL, tc.flags, 0, "192.0.2.2", trans, "192.0.2.2", 0)

			// through the wire so gobgp decodes the 2-byte AS_PATH itself
			wire, err := bmp.NewBMPRouteMonitoring(*peer, update).Serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			msg, err := bmp.ParseBMPMessage(wire)
			if err != nil {
				t.Fatalf("ParseBMPMessage: %v", err)
			}

			out, ok := updateFromBMP(msg)
			if !ok || len(out.Reach) != 1 {
				t.Fatalf("updateFromBMP = %+v ok=%v, want one route", out, ok)
			}
			route := out.Reach[0]
			if !slices.Equal(route.ASPath, tc.wantPath) || route.OriginASN != tc.origin || route.OriginASSet != tc.asSet {
				t.Fatalf("path %v origin %d set %v, want path %v origin %d set %v",
					route.ASPath, route.OriginASN, route.OriginASSet, tc.wantPath, tc.origin, tc.asSet)
			}
		})
	}
}

func TestOriginFromASSetIsFlagged(t *testing.T) {
	update := bgp.NewBGPUpdateMessage(
		nil,
		[]bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
				bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65010}),
				bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65020, 65030}),
			}),
			bgp.NewPathAttributeNextHop("192.0.2.1"),
		},
		[]*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "203.0.113.0")},
	)
	peer := bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_LOCAL_RIB, 0, 0, "192.0.2.2", 65010, "192.0.2.2", 0)

	out, ok := updateFromBMP(bmp.NewBMPRouteMonitoring(*peer, update))
	if !ok || len(out.Reach) != 1 {
		t.Fatalf("updateFromBMP = %+v ok=%v, want one route", out, ok)
	}
	route := out.Reach[0]
	if route.OriginASN != 0 || !route.OriginASSet {
		t.Fatalf("route = origin %d set=%v, want an ambiguous AS_SET origin", route.OriginASN, route.OriginASSet)
	}
	if got, want := route.ASPath, []uint32{65010, 65020, 65030}; len(got) != len(want) || got[0] != want[0] || got[2] != want[2] {
		t.Fatalf("ASPath = %v, want %v", got, want)
	}
	if out.Peer.Address != netip.MustParseAddr("192.0.2.2") || out.Peer.PostPolicy {
		t.Fatalf("update peer = %+v, want the pre policy view of 192.0.2.2", out.Peer)
	}
}
