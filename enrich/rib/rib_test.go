package rib

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
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
		Withdraw: []Withdrawal{{Prefix: pfx}},
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
		Withdraw: []Withdrawal{{Prefix: netip.MustParsePrefix("203.0.113.0/24")}},
	})
	if got := len(tab.metas); got != 1 {
		t.Fatalf("metadata entries after single withdraw = %d, want 1", got)
	}

	tab.Apply(Update{
		Withdraw: []Withdrawal{{Prefix: netip.MustParsePrefix("203.0.114.0/24")}},
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

func TestHandleConnDecodesAddPath(t *testing.T) {
	s := &Server{table: NewTable()}
	client, done := startSession(t, s)

	// the monitored router offered to receive paths and the peer to send
	// them, so every update from the peer carries a path id
	write(t, client, mustAddPathPeerUpWire(t, "192.0.2.2", bgp.BGP_ADD_PATH_RECEIVE, bgp.BGP_ADD_PATH_SEND))
	write(t, client, mustAddPathWire(t, "203.0.113.0/24", 0x01020304, 65002, false))
	write(t, client, mustAddPathWire(t, "203.0.113.0/24", 1, 65001, false))
	waitForSummary(t, s, Summary{PrefixesV4: 1, Routes: 2, Peers: 1})

	// the view serves its lowest path id
	route, ok := s.Lookup(netip.MustParseAddr("203.0.113.7"))
	if !ok || route.OriginASN != 65001 || route.Prefix != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("Lookup = %+v ok=%v, want 203.0.113.0/24 from 65001", route, ok)
	}

	// a withdraw takes one path and leaves the other
	write(t, client, mustAddPathWire(t, "203.0.113.0/24", 1, 0, true))
	waitForSummary(t, s, Summary{PrefixesV4: 1, Routes: 1, Peers: 1})
	if route, ok := s.Lookup(netip.MustParseAddr("203.0.113.7")); !ok || route.OriginASN != 65002 {
		t.Fatalf("Lookup after withdrawing path 1 = %+v ok=%v, want origin 65002", route, ok)
	}

	write(t, client, mustAddPathWire(t, "203.0.113.0/24", 0x01020304, 0, true))
	waitForSummary(t, s, Summary{})

	_ = client.Close()
	<-done
}

func TestHandleConnWithoutAddPath(t *testing.T) {
	s := &Server{table: NewTable()}
	client, done := startSession(t, s)

	// one side alone does not enable ADD-PATH
	write(t, client, mustAddPathPeerUpWire(t, "192.0.2.2", bgp.BGP_ADD_PATH_RECEIVE, bgp.BGP_ADD_PATH_RECEIVE))
	write(t, client, mustBMPWireFrom(t, "203.0.113.0/24", 65002, "192.0.2.2", 0))
	waitForSummary(t, s, Summary{PrefixesV4: 1, Routes: 1, Peers: 1})

	_ = client.Close()
	<-done
}

func TestAddPathOptions(t *testing.T) {
	open := func(tuples ...*bgp.CapAddPathTuple) *bgp.BGPMessage {
		return bgp.NewBGPOpenMessage(65000, 90, "192.0.2.9", []bgp.OptionParameterInterface{
			bgp.NewOptionParameterCapability([]bgp.ParameterCapabilityInterface{bgp.NewCapAddPath(tuples)}),
		})
	}
	tuple := bgp.NewCapAddPathTuple

	for _, tc := range []struct {
		name           string
		sent, received *bgp.BGPMessage
		want           map[bgp.RouteFamily]bgp.BGPAddPathMode
	}{
		{
			name:     "both ways",
			sent:     open(tuple(bgp.RF_IPv4_UC, bgp.BGP_ADD_PATH_BOTH)),
			received: open(tuple(bgp.RF_IPv4_UC, bgp.BGP_ADD_PATH_BOTH)),
			want:     map[bgp.RouteFamily]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_RECEIVE},
		},
		{
			// the router sends paths to the peer, what it receives has none
			name:     "router sends",
			sent:     open(tuple(bgp.RF_IPv4_UC, bgp.BGP_ADD_PATH_SEND)),
			received: open(tuple(bgp.RF_IPv4_UC, bgp.BGP_ADD_PATH_RECEIVE)),
		},
		{
			name:     "per family",
			sent:     open(tuple(bgp.RF_IPv4_UC, bgp.BGP_ADD_PATH_RECEIVE), tuple(bgp.RF_IPv6_UC, bgp.BGP_ADD_PATH_RECEIVE)),
			received: open(tuple(bgp.RF_IPv6_UC, bgp.BGP_ADD_PATH_SEND)),
			want:     map[bgp.RouteFamily]bgp.BGPAddPathMode{bgp.RF_IPv6_UC: bgp.BGP_ADD_PATH_RECEIVE},
		},
		{
			name:     "no capability",
			sent:     bgp.NewBGPOpenMessage(65000, 90, "192.0.2.9", nil),
			received: bgp.NewBGPOpenMessage(65000, 90, "192.0.2.9", nil),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := addPathOptions(&bmp.BMPPeerUpNotification{SentOpenMsg: tc.sent, ReceivedOpenMsg: tc.received})
			var got map[bgp.RouteFamily]bgp.BGPAddPathMode
			if len(opts) > 0 {
				got = opts[0].AddPath
			}
			if !maps.Equal(got, tc.want) {
				t.Fatalf("modes = %v, want %v", got, tc.want)
			}
		})
	}
}

// waitForSummary polls the server until its table summary is want
func waitForSummary(t *testing.T, s *Server, want Summary) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		got := s.Table().Summary()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("summary = %+v, want %+v", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// mustAddPathPeerUpWire serializes a peer up for addr whose sent and
// received OPEN offer ADD-PATH for ipv4 unicast in the given modes
func mustAddPathPeerUpWire(t *testing.T, addr string, sent, received bgp.BGPAddPathMode) []byte {
	t.Helper()

	open := func(mode bgp.BGPAddPathMode) *bgp.BGPMessage {
		return bgp.NewBGPOpenMessage(65000, 90, "192.0.2.9", []bgp.OptionParameterInterface{
			bgp.NewOptionParameterCapability([]bgp.ParameterCapabilityInterface{
				bgp.NewCapAddPath([]*bgp.CapAddPathTuple{bgp.NewCapAddPathTuple(bgp.RF_IPv4_UC, mode)}),
			}),
		})
	}
	peer := bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_GLOBAL, 0, 0, addr, 65000, addr, 0)
	wire, err := bmp.NewBMPPeerUpNotification(*peer, "192.0.2.1", 179, 40000, open(sent), open(received)).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return wire
}

// mustAddPathWire serializes a route monitoring message from 192.0.2.2 that
// announces prefix from origin, or withdraws it, under an ADD-PATH path id
func mustAddPathWire(t *testing.T, prefix string, pathID, origin uint32, withdraw bool) []byte {
	t.Helper()

	return mustAddPathWireFrom(t, "192.0.2.2", prefix, pathID, origin, withdraw)
}

// mustAddPathWireFrom is mustAddPathWire for the peer at addr
func mustAddPathWireFrom(t *testing.T, addr, prefix string, pathID, origin uint32, withdraw bool) []byte {
	t.Helper()

	nlri := bgp.NewIPAddrPrefix(prefixBits(t, prefix), prefixAddr(t, prefix))
	nlri.SetPathLocalIdentifier(pathID)
	update := bgp.NewBGPUpdateMessage([]*bgp.IPAddrPrefix{nlri}, nil, nil)
	if !withdraw {
		update = bgp.NewBGPUpdateMessage(
			nil,
			[]bgp.PathAttributeInterface{
				bgp.NewPathAttributeOrigin(0),
				bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
					bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{origin}),
				}),
				bgp.NewPathAttributeNextHop("192.0.2.1"),
			},
			[]*bgp.IPAddrPrefix{nlri},
		)
	}
	peer := bmp.NewBMPPeerHeader(bmp.BMP_PEER_TYPE_GLOBAL, 0, 0, addr, 65000, addr, 0)
	send := &bgp.MarshallingOption{AddPath: map[bgp.RouteFamily]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND}}
	wire, err := bmp.NewBMPRouteMonitoring(*peer, update).Serialize(send)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return wire
}

func TestHandleConnRecoversFromParseErrors(t *testing.T) {
	s := &Server{table: NewTable()}
	client, done := startSession(t, s)

	asPath := []byte{0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xea} // AS_PATH 65002
	nextHop := []byte{0x40, 3, 4, 192, 0, 2, 1}
	origin := []byte{0x40, 1, 1, 0}

	// an ORIGIN of two bytes makes RFC 7606 treat the update as a withdraw
	// of what it announces, so the route installed before goes away
	write(t, client, mustBMPWire(t, "203.0.113.0/24", 65002))
	waitForRoute(t, s, "203.0.113.7", true)
	write(t, client, rawRouteMonitoring("192.0.2.2", bmp.BMP_PEER_FLAG_POST_POLICY,
		slices.Concat([]byte{0x40, 1, 2, 0, 0}, asPath, nextHop), []byte{24, 203, 0, 113}))
	waitForRoute(t, s, "203.0.113.7", false)

	// a malformed AGGREGATOR is discarded and the route stays valid
	write(t, client, rawRouteMonitoring("192.0.2.2", bmp.BMP_PEER_FLAG_POST_POLICY,
		slices.Concat(origin, asPath, nextHop, []byte{0xc0, 7, 5, 0, 0, 0, 0, 0}), []byte{24, 198, 51, 100}))
	waitForRoute(t, s, "198.51.100.7", true)

	// a peer down whose notification does not parse still names the peer
	write(t, client, rawPeerMessage(bmp.BMP_MSG_PEER_DOWN_NOTIFICATION, "192.0.2.2", []byte{bmp.BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION, 0xff, 0xff}))
	waitForRoute(t, s, "198.51.100.7", false)

	// and so does a peer up whose OPEN messages do not parse
	write(t, client, mustBMPWire(t, "198.51.100.0/24", 65002))
	waitForRoute(t, s, "198.51.100.7", true)
	write(t, client, rawPeerMessage(bmp.BMP_MSG_PEER_UP_NOTIFICATION, "192.0.2.2", make([]byte, 24)))
	waitForRoute(t, s, "198.51.100.7", false)

	// without the capabilities of the peer its updates are dropped, ADD-PATH
	// path id 0x080a0000 would read as 10.0.0.0/8, the route of another
	// peer shows when the session got past it
	write(t, client, mustAddPathWire(t, "203.0.113.0/24", 0x080a0000, 65002, false))
	write(t, client, mustBMPWireFrom(t, "198.51.100.0/24", 65003, "192.0.2.3", 0))
	waitForRoute(t, s, "198.51.100.7", true)
	if route, ok := s.Lookup(netip.MustParseAddr("10.0.0.1")); ok {
		t.Fatalf("Lookup(10.0.0.1) = %+v, want no route read from a path id", route)
	}

	// a peer up that parses makes its updates readable again
	write(t, client, mustAddPathPeerUpWire(t, "192.0.2.2", bgp.BGP_ADD_PATH_RECEIVE, bgp.BGP_ADD_PATH_SEND))
	write(t, client, mustAddPathWire(t, "203.0.113.0/24", 0x080a0000, 65002, false))
	waitForRoute(t, s, "203.0.113.7", true)

	_ = client.Close()
	<-done

	if got := s.Stats().ParseErrors; got != 5 {
		t.Fatalf("parse errors = %d, want 5", got)
	}
}

// rawPeerHeader builds a per peer header for the ipv4 peer addr
func rawPeerHeader(addr string, flags uint8) []byte {
	ip := netip.MustParseAddr(addr).As4()
	h := make([]byte, bmp.BMP_PEER_HEADER_SIZE)
	h[1] = flags
	copy(h[22:26], ip[:])
	binary.BigEndian.PutUint32(h[26:30], 65002)
	copy(h[30:34], ip[:])
	return h
}

// rawPeerMessage builds a BMP message of type with a per peer header for
// addr and body as is
func rawPeerMessage(typ uint8, addr string, body []byte) []byte {
	payload := slices.Concat(rawPeerHeader(addr, 0), body)
	h := []byte{bmp.BMP_VERSION, 0, 0, 0, 0, typ}
	binary.BigEndian.PutUint32(h[1:5], uint32(bmp.BMP_HEADER_SIZE+len(payload)))
	return slices.Concat(h, payload)
}

// rawRouteMonitoring builds a route monitoring message from addr whose
// UPDATE carries attrs and nlri as given, malformed or not
func rawRouteMonitoring(addr string, flags uint8, attrs, nlri []byte) []byte {
	update := make([]byte, 4)
	binary.BigEndian.PutUint16(update[2:4], uint16(len(attrs)))
	update = slices.Concat(update, attrs, nlri)
	header := slices.Concat(bytes.Repeat([]byte{0xff}, 16), []byte{0, 0, bgp.BGP_MSG_UPDATE})
	binary.BigEndian.PutUint16(header[16:18], uint16(len(header)+len(update)))

	payload := slices.Concat(rawPeerHeader(addr, flags), header, update)
	h := []byte{bmp.BMP_VERSION, 0, 0, 0, 0, bmp.BMP_MSG_ROUTE_MONITORING}
	binary.BigEndian.PutUint32(h[1:5], uint32(bmp.BMP_HEADER_SIZE+len(payload)))
	return slices.Concat(h, payload)
}

func TestHandleConnBuffersLazily(t *testing.T) {
	const sessions = 64
	s := &Server{table: NewTable()}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	// one small message per session, so every session has read once
	for i := range sessions {
		client, _ := startSession(t, s)
		write(t, client, mustBMPWire(t, fmt.Sprintf("203.0.%d.0/24", i), 65002))
	}
	waitForSummary(t, s, Summary{PrefixesV4: sessions, Routes: sessions, Peers: 1})

	runtime.GC()
	runtime.ReadMemStats(&after)

	// a session that allocates its buffer for the largest message up front
	// holds 64 KiB however little the speaker sends
	perSession := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / sessions
	t.Logf("heap per session: %d bytes", perSession)
	if perSession > 16<<10 {
		t.Fatalf("heap per session = %d bytes, want at most 16 KiB", perSession)
	}
}

func TestServerLimitsSessions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	s := newServer(ln)
	s.maxSessions = 2
	s.wg.Add(1)
	go s.accept()
	defer s.Close()

	dial := func() net.Conn {
		t.Helper()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	waitForSessions := func(want int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for s.Stats().Sessions != want {
			if time.Now().After(deadline) {
				t.Fatalf("sessions = %d, want %d", s.Stats().Sessions, want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	first := dial()
	dial()
	waitForSessions(2)

	// the session over the limit is closed right away
	extra := dial()
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read on the session over the limit = %v, want EOF", err)
	}
	if got := s.Stats().SessionsRejected; got != 1 {
		t.Fatalf("rejected sessions = %d, want 1", got)
	}

	// a closed session makes room again
	_ = first.Close()
	waitForSessions(1)
	dial()
	waitForSessions(2)
}

func TestHandleConnBoundsAddPathPeers(t *testing.T) {
	const peers = 1 << 14

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	// one session brings up many more peers that send ADD-PATH than the
	// table keeps views, 192.0.2.2 first
	s := &Server{table: NewTable()}
	client, done := startSession(t, s)
	wire := mustAddPathPeerUpWire(t, "192.0.2.2", bgp.BGP_ADD_PATH_RECEIVE, bgp.BGP_ADD_PATH_SEND)
	for i := range peers {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
		wire = append(wire, mustAddPathPeerUpWire(t, addr, bgp.BGP_ADD_PATH_RECEIVE, bgp.BGP_ADD_PATH_SEND)...)
		if len(wire) >= 1<<16 || i == peers-1 {
			write(t, client, wire)
			wire = wire[:0]
		}
	}
	// past the peers it tracks the session cannot tell which peers send
	// ADD-PATH, so it drops the updates of every peer it does not track,
	// one past the limit whose path id 0x080a0000 would read as 10.0.0.0/8
	// and one without ADD-PATH, and it still reads those of 192.0.2.2,
	// which land after all peer ups as the session reads in order
	write(t, client, mustAddPathWireFrom(t, "10.0.63.255", "198.51.100.0/24", 0x080a0000, 65003, false))
	write(t, client, mustBMPWireFrom(t, "192.0.2.0/24", 65004, "192.0.2.4", 0))
	write(t, client, mustAddPathWire(t, "203.0.113.0/24", 0x080a0000, 65002, false))
	waitForRoute(t, s, "203.0.113.7", true)
	for _, addr := range []string{"10.0.0.1", "198.51.100.7", "192.0.2.7"} {
		if route, ok := s.Lookup(netip.MustParseAddr(addr)); ok {
			t.Fatalf("Lookup(%s) = %+v, want no route from a peer the session does not track", addr, route)
		}
	}
	if got := s.Stats().ParseErrors; got != 2 {
		t.Fatalf("parse errors = %d, want the 2 updates dropped", got)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	perPeer := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / peers
	t.Logf("heap per peer: %d bytes", perPeer)
	if perPeer > 64 {
		t.Fatalf("heap per peer = %d bytes, want at most 64", perPeer)
	}

	_ = client.Close()
	<-done
}

func TestTableLimitsRoutes(t *testing.T) {
	tab := NewTable()
	tab.maxRoutes = 2
	peer := netip.MustParseAddr("192.0.2.1")
	route := func(prefix string, origin uint32) Route {
		return Route{Prefix: netip.MustParsePrefix(prefix), OriginASN: origin, PeerAddress: peer}
	}

	tab.Apply(Update{Reach: []Route{route("203.0.113.0/24", 1), route("198.51.100.0/24", 1), route("192.0.2.0/24", 1)}})
	if got := tab.Summary(); got.Routes != 2 {
		t.Fatalf("routes = %d, want the limit of 2", got.Routes)
	}
	if _, ok := tab.Lookup(netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("route past the limit was stored")
	}
	if got := tab.rejected.Load(); got != 1 {
		t.Fatalf("rejected routes = %d, want 1", got)
	}

	// a route that replaces one the table holds does not grow it
	tab.Apply(Update{Reach: []Route{route("203.0.113.0/24", 2)}})
	if r, ok := tab.Lookup(netip.MustParseAddr("203.0.113.1")); !ok || r.OriginASN != 2 {
		t.Fatalf("replaced route = %+v ok=%v, want origin 2", r, ok)
	}

	// a withdraw makes room again
	tab.Apply(Update{Peer: Peer{Address: peer}, Withdraw: []Withdrawal{{Prefix: netip.MustParsePrefix("198.51.100.0/24")}}})
	tab.Apply(Update{Reach: []Route{route("192.0.2.0/24", 1)}})
	if _, ok := tab.Lookup(netip.MustParseAddr("192.0.2.1")); !ok {
		t.Fatal("route not stored after a withdraw made room")
	}
	if got := tab.rejected.Load(); got != 1 {
		t.Fatalf("rejected routes = %d, want 1", got)
	}

	// another ADD-PATH path of a prefix the table holds takes room
	extra := route("203.0.113.0/24", 3)
	extra.PathID = 7
	tab.Apply(Update{Reach: []Route{extra}})
	if got := tab.Summary(); got.Routes != 2 || tab.rejected.Load() != 2 {
		t.Fatalf("routes = %d rejected = %d, want 2 and 2", got.Routes, tab.rejected.Load())
	}
	checkInvariants(t, tab)
}

func TestTableLimitsViews(t *testing.T) {
	tab := NewTable()
	tab.maxViews = 2
	prefix := netip.MustParsePrefix("203.0.113.0/24")

	for _, addr := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		tab.Apply(Update{Reach: []Route{{Prefix: prefix, OriginASN: 1, PeerAddress: netip.MustParseAddr(addr)}}})
	}
	if got := tab.Summary(); got.Peers != 2 || got.Routes != 2 {
		t.Fatalf("summary = %+v, want the limit of 2 views", got)
	}
	if got := tab.rejected.Load(); got != 1 {
		t.Fatalf("rejected routes = %d, want 1", got)
	}

	// a view the table holds still takes more routes
	tab.Apply(Update{Reach: []Route{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), PeerAddress: netip.MustParseAddr("192.0.2.1")}}})
	if got := tab.Summary(); got.Routes != 3 {
		t.Fatalf("routes = %d, want 3", got.Routes)
	}
	checkInvariants(t, tab)
}

// uniqueAttrsRoute returns route i of a speaker that gives every route an
// AS path and communities of its own, pathLen ASNs, n communities and n
// large communities
func uniqueAttrsRoute(i, pathLen, n int) Route {
	route := Route{
		Prefix:      netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(1 + i>>16), byte(i >> 8), byte(i), 0}), 24),
		PeerASN:     64496,
		PeerAddress: netip.MustParseAddr("192.0.2.1"),
	}
	for j := range pathLen {
		route.ASPath = append(route.ASPath, uint32(4200000000+i*pathLen+j))
	}
	route.OriginASN = route.ASPath[pathLen-1]
	for j := range n {
		route.Communities = append(route.Communities, uint32(i*n+j))
		route.LargeCommunities = append(route.LargeCommunities, LargeCommunity{GlobalAdmin: 4200000000, LocalData1: uint32(i), LocalData2: uint32(j)})
	}
	return route
}

func TestTableKeepsLeadingAttributes(t *testing.T) {
	tab := NewTable()
	route := uniqueAttrsRoute(0, 1000, 1000)
	tab.Apply(Update{Reach: []Route{route}})

	// labels need only the origin, which the route keeps whatever its
	// path holds
	addr := netip.MustParseAddr("1.0.0.1")
	if labels, _ := tab.Enrich(addr, addr); labels.ASN != route.OriginASN {
		t.Fatalf("label = %d, want the origin %d", labels.ASN, route.OriginASN)
	}

	// a lookup shows the leading part of each list and that it is cut
	got, ok := tab.Lookup(addr)
	if !ok || got.OriginASN != route.OriginASN || !got.Truncated {
		t.Fatalf("Lookup = origin %d truncated=%v ok=%v, want origin %d truncated", got.OriginASN, got.Truncated, ok, route.OriginASN)
	}
	if !slices.Equal(got.ASPath, route.ASPath[:maxPathLen]) {
		t.Fatalf("as path holds %d ASNs, want the leading %d", len(got.ASPath), maxPathLen)
	}
	if !slices.Equal(got.Communities, route.Communities[:maxCommunities]) {
		t.Fatalf("communities hold %d values, want the leading %d", len(got.Communities), maxCommunities)
	}
	if !slices.Equal(got.LargeCommunities, route.LargeCommunities[:maxCommunities]) {
		t.Fatalf("large communities hold %d values, want the leading %d", len(got.LargeCommunities), maxCommunities)
	}

	// a route whose lists fit is whole, though the table keeps the same
	// values for the cut one
	whole := route
	whole.Prefix = netip.MustParsePrefix("2.0.0.0/24")
	whole.ASPath = got.ASPath
	whole.Communities = got.Communities
	whole.LargeCommunities = got.LargeCommunities
	tab.Apply(Update{Reach: []Route{whole}})
	if got, ok := tab.Lookup(netip.MustParseAddr("2.0.0.1")); !ok || got.Truncated || !slices.Equal(got.ASPath, whole.ASPath) {
		t.Fatalf("Lookup = path of %d ASNs truncated=%v ok=%v, want the whole path", len(got.ASPath), got.Truncated, ok)
	}
}

func TestTableHeapPerRouteWithUniqueAttributes(t *testing.T) {
	const n = 1 << 12

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	tab := NewTable()
	batch := make([]Route, 0, 256)
	for i := range n {
		batch = append(batch, uniqueAttrsRoute(i, 64, 256))
		if len(batch) == cap(batch) {
			tab.Apply(Update{Reach: batch})
			batch = batch[:0]
		}
	}
	batch = nil

	runtime.GC()
	runtime.ReadMemStats(&after)
	if got := tab.Summary(); got.Routes != n {
		t.Fatalf("summary = %+v, want %d routes", got, n)
	}
	runtime.KeepAlive(tab)

	// a route with a 64 ASN path and 256 communities of each kind took
	// 13 KiB, so 160k of them filled 2 GiB, a fiftieth of maxRoutes
	perRoute := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / n
	t.Logf("heap per route: %d bytes", perRoute)
	if perRoute > 4<<10 {
		t.Fatalf("heap per route = %d bytes, want at most 4 KiB", perRoute)
	}
}

// failingListener fails every accept with err until it is closed, a
// listener that ran out of file descriptors fails with EMFILE
type failingListener struct {
	err    error
	calls  atomic.Int64
	closed chan struct{}
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
		return nil, l.err
	}
}

func (l *failingListener) Close() error {
	close(l.closed)
	return nil
}

func (l *failingListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func TestAcceptBacksOffOnErrors(t *testing.T) {
	ln := &failingListener{err: syscall.EMFILE, closed: make(chan struct{})}
	s := newServer(ln)
	s.wg.Add(1)
	go s.accept()

	time.Sleep(200 * time.Millisecond)
	calls := ln.calls.Load()

	// a temporary error leaves the listener running, Wait ends with its
	// context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait = %v, want the canceled context", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if calls > 20 {
		t.Fatalf("accept ran %d times in 200ms of errors, want a backoff", calls)
	}
}

func TestAcceptStopsOnPermanentErrors(t *testing.T) {
	ln := &failingListener{err: syscall.EINVAL, closed: make(chan struct{})}
	s := newServer(ln)
	s.wg.Add(1)
	go s.accept()
	defer s.Close()

	// an error that is not temporary stops the listener at once, and Wait
	// hands it to the agent, which fails
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Wait(ctx); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Wait = %v, want the accept error", err)
	}
	if calls := ln.calls.Load(); calls != 1 {
		t.Fatalf("accept ran %d times, want once", calls)
	}
}

func TestServerCloseReturnsWithIdleConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	s := newServer(ln)
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
			// the header is a message that did not parse, a bmp error
			// like any other
			if got := s.Stats().ParseErrors; got != 1 {
				t.Fatalf("parse errors = %d, want the header that ended the session counted", got)
			}
		})
	}
}

func TestServerCloseReturnsAfterZeroLengthHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	s := newServer(ln)
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
	tab.Apply(Update{Peer: a, Withdraw: []Withdrawal{{Prefix: pfx}}})
	route, ok = tab.Lookup(netip.MustParseAddr("203.0.113.9"))
	if !ok || route.OriginASN != 64502 {
		t.Fatalf("route after withdraw = %+v ok=%v, want origin 64502 from the other peer", route, ok)
	}
	if got := tab.Summary(); got.Routes != 1 || got.Peers != 1 {
		t.Fatalf("summary after withdraw = %+v, want 1 route from 1 peer", got)
	}

	tab.Apply(Update{Peer: b, Withdraw: []Withdrawal{{Prefix: pfx}}})
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
	if got := (&Server{table: tab}).Stats().Inconsistencies; got != 4 {
		t.Fatalf("inconsistencies = %d, want 4", got)
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

// ribModel is the obvious RIB the table must agree with, every path per
// view and prefix keyed by path id, a view serves its lowest path id and a
// linear search picks the best view
type ribModel map[Peer]map[netip.Prefix]map[uint32]uint32

// served returns the path id and origin a view serves for prefix
func (m ribModel) served(peer Peer, prefix netip.Prefix) (uint32, uint32, bool) {
	paths := m[peer][prefix]
	if len(paths) == 0 {
		return 0, 0, false
	}
	id := slices.Min(slices.Collect(maps.Keys(paths)))
	return id, paths[id], true
}

func (m ribModel) best(prefix netip.Prefix) (Peer, uint32, uint32, bool) {
	var best Peer
	var pathID, origin uint32
	found := false
	for peer := range m {
		if id, o, ok := m.served(peer, prefix); ok && (!found || betterPeer(peer, best)) {
			best, pathID, origin, found = peer, id, o, true
		}
	}
	return best, pathID, origin, found
}

func (m ribModel) lookup(addr netip.Addr) (netip.Prefix, Peer, uint32, uint32, bool) {
	for bits := addr.BitLen(); bits >= 0; bits-- {
		prefix, _ := addr.Prefix(bits)
		if peer, pathID, origin, ok := m.best(prefix); ok {
			return prefix, peer, pathID, origin, true
		}
	}
	return netip.Prefix{}, Peer{}, 0, 0, false
}

func (m ribModel) reach(peer Peer, prefix netip.Prefix, pathID, origin uint32) {
	if m[peer] == nil {
		m[peer] = make(map[netip.Prefix]map[uint32]uint32)
	}
	if m[peer][prefix] == nil {
		m[peer][prefix] = make(map[uint32]uint32)
	}
	m[peer][prefix][pathID] = origin
}

func (m ribModel) withdraw(peer Peer, prefix netip.Prefix, pathID uint32) {
	delete(m[peer][prefix], pathID)
	if len(m[peer][prefix]) == 0 {
		delete(m[peer], prefix)
	}
	if len(m[peer]) == 0 {
		delete(m, peer)
	}
}

func (m ribModel) check(t *testing.T, tab *Table, probes []netip.Addr, step int) {
	t.Helper()

	var want Summary
	prefixes := make(map[netip.Prefix]struct{})
	metas := make(map[[2]any]struct{})
	for peer, routes := range m {
		want.Peers++
		for prefix, paths := range routes {
			prefixes[prefix] = struct{}{}
			for _, origin := range paths {
				want.Routes++
				metas[[2]any{peer, origin}] = struct{}{}
			}
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
		prefix, peer, pathID, origin, ok := m.lookup(addr)
		route, gotOK := tab.Lookup(addr)
		if gotOK != ok || route.Prefix != prefix || route.OriginASN != origin || route.Peer() != peer || route.PathID != pathID {
			t.Fatalf("step %d: Lookup(%s) = %s path %d origin %d from %+v ok=%v, want %s path %d origin %d from %+v ok=%v",
				step, addr, route.Prefix, route.PathID, route.OriginASN, route.Peer(), gotOK, prefix, pathID, origin, peer, ok)
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
	for step := range 6000 {
		peer := peers[rng.IntN(len(peers))]
		prefix := prefixes[rng.IntN(len(prefixes))]
		// path ids 0 to 3 give a view up to four paths for a prefix
		pathID := uint32(rng.IntN(4))
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
				PathID:            pathID,
			}}})
			model.reach(peer, prefix, pathID, origin)
		case op < 8:
			tab.Apply(Update{Peer: peer, Withdraw: []Withdrawal{{Prefix: prefix, PathID: pathID}}})
			model.withdraw(peer, prefix, pathID)
		case op < 9:
			tab.Apply(Update{Withdraw: []Withdrawal{{Prefix: prefix, PathID: pathID}}})
			for peer := range model {
				model.withdraw(peer, prefix, pathID)
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
		for prefix, head := range v.routes.All() {
			if _, ok := tab.best.Get(prefix); !ok {
				t.Fatalf("%s of %+v is missing from best", prefix, v.peer)
			}
			ids := map[uint32]bool{head.pathID: true}
			for _, path := range v.more[prefix] {
				if path.pathID <= head.pathID || ids[path.pathID] {
					t.Fatalf("%s of %+v serves path %d next to path %d", prefix, v.peer, head.pathID, path.pathID)
				}
				ids[path.pathID] = true
			}
		}
		for prefix, paths := range v.more {
			if _, ok := v.routes.Get(prefix); !ok || len(paths) == 0 {
				t.Fatalf("%s of %+v keeps %d other paths and no served one", prefix, v.peer, len(paths))
			}
			routes += len(paths)
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
			tab.Apply(Update{Peer: Peer{Address: b}, Withdraw: []Withdrawal{{Prefix: prefix}}})
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
