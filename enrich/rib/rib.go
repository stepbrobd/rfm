package rib

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/gaissmai/bart"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
)

const (
	// bmpScannerInitialBuf is the starting buffer size for the BMP message scanner
	bmpScannerInitialBuf = 64 * 1024
	// bmpScannerMaxBuf caps BMP message size, very big and prob not necessary (just in case)
	bmpScannerMaxBuf = 1 << 20
)

// LargeCommunity is a decoded RFC 8092 large community
type LargeCommunity struct {
	GlobalAdmin uint32
	LocalData1  uint32
	LocalData2  uint32
}

// Peer identifies one view of the routing table as seen over BMP
// a speaker sends one view per monitored peer and, when configured, one
// each for pre and post policy, routes are kept per view so a withdraw from
// one peer never removes what another peer still announces
type Peer struct {
	Address       netip.Addr
	Distinguisher uint64
	PostPolicy    bool
}

// Route is the internal route view exposed by the RIB backend
type Route struct {
	Prefix    netip.Prefix
	OriginASN uint32
	// OriginASSet marks a path whose last segment is an AS_SET, the origin
	// is then ambiguous and OriginASN is 0
	OriginASSet       bool
	ASPath            []uint32
	Communities       []uint32
	LargeCommunities  []LargeCommunity
	PeerASN           uint32
	PeerAddress       netip.Addr
	PeerDistinguisher uint64
	PostPolicy        bool
}

// Peer returns the view this route belongs to
func (r Route) Peer() Peer {
	return Peer{Address: r.PeerAddress, Distinguisher: r.PeerDistinguisher, PostPolicy: r.PostPolicy}
}

type routeValue struct {
	Prefix      netip.Prefix
	OriginASN   uint32
	OriginASSet bool
	MetaID      uint64
}

type routeMeta struct {
	ASPath            []uint32
	Communities       []uint32
	LargeCommunities  []LargeCommunity
	PeerASN           uint32
	PeerAddress       netip.Addr
	PeerDistinguisher uint64
	PostPolicy        bool
}

type routeMetaKey struct {
	ASPath            string
	Communities       string
	LargeCommunities  string
	PeerASN           uint32
	PeerAddress       netip.Addr
	PeerDistinguisher uint64
	PostPolicy        bool
}

type routeMetaState struct {
	key  routeMetaKey
	meta routeMeta
	refs int
}

// Update is a batch of RIB changes
// Reach routes carry their own peer, Withdraw prefixes are withdrawn from
// Peer, or from every peer when Peer is the zero value
type Update struct {
	Peer     Peer
	Reach    []Route
	Withdraw []netip.Prefix
}

// Summary counts what the table holds
type Summary struct {
	PrefixesV4 int
	PrefixesV6 int
	Routes     int
	Peers      int
}

// Table is a longest-prefix-match routing table
// the tries hold the best route per prefix, entries hold every route per
// prefix and peer so the best route can be reselected on a withdraw
type Table struct {
	mu         sync.RWMutex
	v4         bart.Table[routeValue]
	v6         bart.Table[routeValue]
	entries    map[netip.Prefix]map[Peer]routeValue
	peerRoutes map[Peer]int
	metas      map[uint64]*routeMetaState
	metaKeys   map[routeMetaKey]uint64
	nextMeta   uint64
}

// NewTable creates an empty RIB table
func NewTable() *Table {
	return &Table{
		entries:    make(map[netip.Prefix]map[Peer]routeValue),
		peerRoutes: make(map[Peer]int),
		metas:      make(map[uint64]*routeMetaState),
		metaKeys:   make(map[routeMetaKey]uint64),
		nextMeta:   1,
	}
}

// Apply applies a batch of route updates
func (t *Table) Apply(update Update) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, prefix := range update.Withdraw {
		prefix = prefix.Masked()
		if update.Peer == (Peer{}) {
			for peer := range t.entries[prefix] {
				t.deleteRoute(prefix, peer)
			}
			continue
		}
		t.deleteRoute(prefix, update.Peer)
	}
	for _, route := range update.Reach {
		t.insertRoute(route)
	}
}

// RemovePeer withdraws every route learned from peer
func (t *Table) RemovePeer(peer Peer) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.peerRoutes[peer] == 0 {
		return
	}
	for prefix, peers := range t.entries {
		if _, ok := peers[peer]; ok {
			t.deleteRoute(prefix, peer)
		}
	}
}

// Lookup returns the best matching route for addr
func (t *Table) Lookup(addr netip.Addr) (Route, bool) {
	addr = addr.Unmap()

	t.mu.RLock()
	defer t.mu.RUnlock()

	value, ok := lookupTable(&t.v4, &t.v6, addr)
	if !ok {
		return Route{}, false
	}
	return t.route(value), true
}

// Enrich returns only the labels Prometheus needs
func (t *Table) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	return t.labels(src), t.labels(dst)
}

func (t *Table) labels(addr netip.Addr) collector.Labels {
	addr = addr.Unmap()

	t.mu.RLock()
	defer t.mu.RUnlock()

	value, ok := lookupTable(&t.v4, &t.v6, addr)
	if !ok {
		return collector.Labels{}
	}
	return collector.Labels{ASN: value.OriginASN}
}

// Summary counts the prefixes, routes and peers in the table
func (t *Table) Summary() Summary {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var routes int
	for _, n := range t.peerRoutes {
		routes += n
	}
	return Summary{
		PrefixesV4: t.v4.Size(),
		PrefixesV6: t.v6.Size(),
		Routes:     routes,
		Peers:      len(t.peerRoutes),
	}
}

// Peers lists the views with at least one route
func (t *Table) Peers() []Peer {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]Peer, 0, len(t.peerRoutes))
	for peer := range t.peerRoutes {
		out = append(out, peer)
	}
	return out
}

// Server owns a BMP listener and an in-memory RIB
type Server struct {
	listener net.Listener
	table    *Table
	done     chan struct{}
	wg       sync.WaitGroup
	connsMu  sync.Mutex
	conns    map[net.Conn]struct{}
	closing  bool
}

// Listen starts a BMP listener when configured
// When BMP listen is unset, it returns nil, nil, nil
func Listen(cfg config.RIBConfig) (collector.Enricher, io.Closer, error) {
	bmpCfg := cfg.BMP.WithDefaults()
	if !bmpCfg.Enabled() {
		return nil, nil, nil
	}

	addr := bmpCfg.Addr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen BMP %q: %w", addr, err)
	}

	s := &Server{
		listener: ln,
		table:    NewTable(),
		done:     make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}
	s.wg.Add(1)
	go s.accept()

	return s, s, nil
}

func (s *Server) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	return s.table.Enrich(src, dst)
}

// Lookup returns the best matching route for addr
func (s *Server) Lookup(addr netip.Addr) (Route, bool) {
	return s.table.Lookup(addr)
}

// Table exposes the RIB for inspection
func (s *Server) Table() *Table {
	return s.table
}

func (s *Server) Close() error {
	s.connsMu.Lock()
	s.closing = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.connsMu.Unlock()

	close(s.done)

	for _, conn := range conns {
		_ = conn.Close()
	}

	err := s.listener.Close()
	s.wg.Wait()
	return err
}

func (s *Server) accept() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		if !s.trackConn(conn) {
			continue
		}

		s.wg.Add(1)
		go func(conn net.Conn) {
			defer s.wg.Done()
			defer s.untrackConn(conn)
			defer conn.Close()
			s.handleConn(conn)
		}(conn)
	}
}

// handleConn reads one BMP session
// a peer down message withdraws that peer, and a peer up message withdraws
// what an earlier session announced for the peer, because the speaker dumps
// the peer's table again right after it, routes survive the end of a session
// so a speaker restart leaves enrichment in place until the next dump
func (s *Server) handleConn(conn net.Conn) {
	log.Info("bmp session opened", "remote", conn.RemoteAddr())

	scanner := bufio.NewScanner(conn)
	scanner.Split(splitBMP)
	scanner.Buffer(make([]byte, bmpScannerInitialBuf), bmpScannerMaxBuf)

	var messages int
	var changes int
	var parseErrLogged bool
	var appliedLogged bool
	seenTypes := make(map[uint8]struct{})
	peers := make(map[Peer]struct{})

	for scanner.Scan() {
		messages++

		msg, err := bmp.ParseBMPMessage(scanner.Bytes())
		if err != nil {
			if !parseErrLogged {
				log.Error("parse bmp message", "remote", conn.RemoteAddr(), "err", err)
				parseErrLogged = true
			}
			continue
		}

		if msg.Header.Type != bmp.BMP_MSG_ROUTE_MONITORING {
			if _, ok := seenTypes[msg.Header.Type]; !ok {
				log.Info("bmp message received", "remote", conn.RemoteAddr(), "type", msg.Header.Type)
				seenTypes[msg.Header.Type] = struct{}{}
			}
		}

		switch msg.Header.Type {
		case bmp.BMP_MSG_PEER_UP_NOTIFICATION:
			peer := peerFromHeader(msg.PeerHeader)
			s.table.RemovePeer(peer)
			log.Info("bmp peer up", "remote", conn.RemoteAddr(), "peer", peer.Address)
			continue
		case bmp.BMP_MSG_PEER_DOWN_NOTIFICATION:
			peer := peerFromHeader(msg.PeerHeader)
			s.table.RemovePeer(peer)
			delete(peers, peer)
			log.Info("bmp peer down", "remote", conn.RemoteAddr(), "peer", peer.Address)
			continue
		case bmp.BMP_MSG_ROUTE_MONITORING:
			log.Debug(
				"bmp route monitoring raw",
				"remote", conn.RemoteAddr(),
				"summary", describeRouteMonitoring(msg),
			)
		}

		update, ok := updateFromBMP(msg)
		if !ok {
			continue
		}
		peers[update.Peer] = struct{}{}

		if len(update.Reach) > 0 || len(update.Withdraw) > 0 {
			if !appliedLogged {
				log.Info(
					"bmp route monitoring applied",
					"remote", conn.RemoteAddr(),
					"reach", len(update.Reach),
					"withdraw", len(update.Withdraw),
				)
				appliedLogged = true
			}

			log.Debug(
				"bmp route monitoring applied",
				"remote", conn.RemoteAddr(),
				"reach", len(update.Reach),
				"withdraw", len(update.Withdraw),
			)
		}

		changes += len(update.Reach) + len(update.Withdraw)
		s.table.Apply(update)
	}

	if err := scanner.Err(); err != nil && !s.isClosing() {
		log.Error("read bmp stream", "remote", conn.RemoteAddr(), "err", err)
	}

	log.Info("bmp session closed", "remote", conn.RemoteAddr(), "messages", messages, "changes", changes, "peers", len(peers))
}

// errBMPLength ends a session whose header announces a length no message
// can have
var errBMPLength = errors.New("bmp message length out of bounds")

// errBMPVersion ends a session whose speaker sends a version other than the
// one RFC 7854 defines
var errBMPVersion = errors.New("unsupported bmp version")

// splitBMP frames BMP messages like bmp.SplitBMP but fails on a version
// other than 3 and on a length shorter than the common header or longer
// than the scanner buffers
// SplitBMP hands back an empty token for a zero length, which the scanner
// returns forever without reading again, waits for more data after a
// header of another version, and waits for the rest of a message that
// cannot fit until the buffer limit ends the session
func splitBMP(data []byte, atEOF bool) (int, []byte, error) {
	if len(data) > 0 && data[0] != bmp.BMP_VERSION {
		return 0, nil, fmt.Errorf("%w %d, rfm reads version %d from rfc 7854", errBMPVersion, data[0], bmp.BMP_VERSION)
	}
	if len(data) >= bmp.BMP_HEADER_SIZE {
		if n := binary.BigEndian.Uint32(data[1:5]); n < bmp.BMP_HEADER_SIZE || n > bmpScannerMaxBuf {
			return 0, nil, fmt.Errorf("%w: %d bytes", errBMPLength, n)
		}
	}
	return bmp.SplitBMP(data, atEOF)
}

func (s *Server) trackConn(conn net.Conn) bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	if s.closing {
		_ = conn.Close()
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) untrackConn(conn net.Conn) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()

	delete(s.conns, conn)
}

func (s *Server) isClosing() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func peerFromHeader(h bmp.BMPPeerHeader) Peer {
	peer := Peer{Distinguisher: h.PeerDistinguisher, PostPolicy: h.IsPostPolicy()}
	if addr, ok := netip.AddrFromSlice(h.PeerAddress); ok {
		peer.Address = addr.Unmap()
	}
	return peer
}

func updateFromBMP(msg *bmp.BMPMessage) (Update, bool) {
	if msg.Header.Type != bmp.BMP_MSG_ROUTE_MONITORING {
		return Update{}, false
	}

	body, ok := msg.Body.(*bmp.BMPRouteMonitoring)
	if !ok || body.BGPUpdate == nil {
		return Update{}, false
	}

	updateMsg, ok := body.BGPUpdate.Body.(*bgp.BGPUpdate)
	if !ok {
		return Update{}, false
	}

	attrs := routeAttrs(updateMsg.PathAttributes)

	out := Update{Peer: peerFromHeader(msg.PeerHeader)}
	for _, withdraw := range updateMsg.WithdrawnRoutes {
		if prefix, ok := prefixFromNLRI(withdraw); ok {
			out.Withdraw = append(out.Withdraw, prefix)
		}
	}
	for _, nlri := range updateMsg.NLRI {
		if prefix, ok := prefixFromNLRI(nlri); ok {
			out.Reach = append(out.Reach, attrs.route(prefix, msg.PeerHeader))
		}
	}

	for _, attr := range updateMsg.PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			for _, nlri := range a.Value {
				if prefix, ok := prefixFromNLRI(nlri); ok {
					out.Reach = append(out.Reach, attrs.route(prefix, msg.PeerHeader))
				}
			}
		case *bgp.PathAttributeMpUnreachNLRI:
			for _, nlri := range a.Value {
				if prefix, ok := prefixFromNLRI(nlri); ok {
					out.Withdraw = append(out.Withdraw, prefix)
				}
			}
		}
	}

	return out, true
}

func describeRouteMonitoring(msg *bmp.BMPMessage) string {
	body, ok := msg.Body.(*bmp.BMPRouteMonitoring)
	if !ok || body.BGPUpdate == nil {
		return "missing bgp update"
	}

	out := []string{
		fmt.Sprintf("bgp_type=%d", body.BGPUpdate.Header.Type),
	}

	update, ok := body.BGPUpdate.Body.(*bgp.BGPUpdate)
	if !ok {
		return strings.Join(out, " ")
	}

	end, rf := update.IsEndOfRib()
	out = append(
		out,
		fmt.Sprintf("eor=%t", end),
		fmt.Sprintf("rf=%d", rf),
		fmt.Sprintf("nlri=%d", len(update.NLRI)),
		fmt.Sprintf("withdraw=%d", len(update.WithdrawnRoutes)),
		fmt.Sprintf("attrs=%d", len(update.PathAttributes)),
	)

	if len(update.NLRI) > 0 {
		out = append(out, "nlri0="+describePrefix(update.NLRI[0]))
	}
	if len(update.WithdrawnRoutes) > 0 {
		out = append(out, "withdraw0="+describePrefix(update.WithdrawnRoutes[0]))
	}

	for _, attr := range update.PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			out = append(
				out,
				fmt.Sprintf("mp_reach=%d", len(a.Value)),
			)
			if len(a.Value) > 0 {
				out = append(out, "mp_reach0="+describePrefix(a.Value[0]))
			}
		case *bgp.PathAttributeMpUnreachNLRI:
			out = append(
				out,
				fmt.Sprintf("mp_unreach=%d", len(a.Value)),
			)
			if len(a.Value) > 0 {
				out = append(out, "mp_unreach0="+describePrefix(a.Value[0]))
			}
		}
	}

	return strings.Join(out, " ")
}

func describePrefix(nlri bgp.AddrPrefixInterface) string {
	if prefix, ok := prefixFromNLRI(nlri); ok {
		return prefix.String()
	}

	flat := nlri.Flat()
	if len(flat) == 0 {
		return nlri.String()
	}

	return fmt.Sprintf("%s flat=%v", nlri.String(), flat)
}

// insertRoute stores route under its peer and reselects the best route
// it must be called with mu held
func (t *Table) insertRoute(route Route) {
	route.Prefix = route.Prefix.Masked()
	peer := route.Peer()

	peers, ok := t.entries[route.Prefix]
	if !ok {
		peers = make(map[Peer]routeValue)
		t.entries[route.Prefix] = peers
	}
	if current, ok := peers[peer]; ok {
		t.releaseMeta(current.MetaID)
	} else {
		t.peerRoutes[peer]++
	}

	peers[peer] = routeValue{
		Prefix:      route.Prefix,
		OriginASN:   route.OriginASN,
		OriginASSet: route.OriginASSet,
		MetaID:      t.internMeta(route.meta()),
	}
	t.reselect(route.Prefix)
}

// deleteRoute drops the route of peer for prefix and reselects the best
// it must be called with mu held
func (t *Table) deleteRoute(prefix netip.Prefix, peer Peer) {
	peers, ok := t.entries[prefix]
	if !ok {
		return
	}
	current, ok := peers[peer]
	if !ok {
		return
	}

	t.releaseMeta(current.MetaID)
	delete(peers, peer)
	if t.peerRoutes[peer]--; t.peerRoutes[peer] == 0 {
		delete(t.peerRoutes, peer)
	}

	if len(peers) == 0 {
		delete(t.entries, prefix)
		deletePrefix(&t.v4, &t.v6, prefix)
		return
	}
	t.reselect(prefix)
}

// reselect installs the best route for prefix in the trie
// a post policy view wins over a pre policy one, then the lowest peer
// address and distinguisher, which keeps the choice stable across updates
// it must be called with mu held
func (t *Table) reselect(prefix netip.Prefix) {
	var best Peer
	var value routeValue
	found := false
	for peer, v := range t.entries[prefix] {
		if !found || betterPeer(peer, best) {
			best, value, found = peer, v, true
		}
	}
	if found {
		insertValue(&t.v4, &t.v6, value)
	}
}

func betterPeer(a, b Peer) bool {
	if a.PostPolicy != b.PostPolicy {
		return a.PostPolicy
	}
	if c := a.Address.Compare(b.Address); c != 0 {
		return c < 0
	}
	return a.Distinguisher < b.Distinguisher
}

func (t *Table) route(value routeValue) Route {
	route := Route{
		Prefix:      value.Prefix,
		OriginASN:   value.OriginASN,
		OriginASSet: value.OriginASSet,
	}
	if value.MetaID == 0 {
		return route
	}

	state, ok := t.metas[value.MetaID]
	if !ok {
		return route
	}

	routeMeta := state.meta.clone()
	route.ASPath = routeMeta.ASPath
	route.Communities = routeMeta.Communities
	route.LargeCommunities = routeMeta.LargeCommunities
	route.PeerASN = routeMeta.PeerASN
	route.PeerAddress = routeMeta.PeerAddress
	route.PeerDistinguisher = routeMeta.PeerDistinguisher
	route.PostPolicy = routeMeta.PostPolicy
	return route
}

func (t *Table) internMeta(meta routeMeta) uint64 {
	if meta.empty() {
		return 0
	}

	key := meta.key()
	if id, ok := t.metaKeys[key]; ok {
		t.metas[id].refs++
		return id
	}

	id := t.nextMeta
	t.nextMeta++
	t.metaKeys[key] = id
	t.metas[id] = &routeMetaState{
		key:  key,
		meta: meta.clone(),
		refs: 1,
	}
	return id
}

func (t *Table) releaseMeta(id uint64) {
	if id == 0 {
		return
	}

	state, ok := t.metas[id]
	if !ok {
		return
	}

	state.refs--
	if state.refs > 0 {
		return
	}

	delete(t.metaKeys, state.key)
	delete(t.metas, id)
}

type attrs struct {
	originASN        uint32
	originASSet      bool
	asPath           []uint32
	communities      []uint32
	largeCommunities []LargeCommunity
}

func routeAttrs(pathAttrs []bgp.PathAttributeInterface) attrs {
	var out attrs

	for _, attr := range pathAttrs {
		switch a := attr.(type) {
		case *bgp.PathAttributeAsPath:
			out.asPath = flattenASPath(a.Value)
			out.originASN, out.originASSet = originASN(a.Value)
		case *bgp.PathAttributeCommunities:
			out.communities = append([]uint32(nil), a.Value...)
		case *bgp.PathAttributeLargeCommunities:
			out.largeCommunities = make([]LargeCommunity, 0, len(a.Values))
			for _, value := range a.Values {
				out.largeCommunities = append(out.largeCommunities, LargeCommunity{
					GlobalAdmin: value.ASN,
					LocalData1:  value.LocalData1,
					LocalData2:  value.LocalData2,
				})
			}
		}
	}

	return out
}

func (a attrs) route(prefix netip.Prefix, peer bmp.BMPPeerHeader) Route {
	route := Route{
		Prefix:            prefix,
		OriginASN:         a.originASN,
		OriginASSet:       a.originASSet,
		ASPath:            append([]uint32(nil), a.asPath...),
		Communities:       append([]uint32(nil), a.communities...),
		LargeCommunities:  append([]LargeCommunity(nil), a.largeCommunities...),
		PeerASN:           peer.PeerAS,
		PeerDistinguisher: peer.PeerDistinguisher,
		PostPolicy:        peer.IsPostPolicy(),
	}

	if addr, ok := netip.AddrFromSlice(peer.PeerAddress); ok {
		route.PeerAddress = addr.Unmap()
	}

	return route
}

func (r Route) meta() routeMeta {
	return routeMeta{
		ASPath:            append([]uint32(nil), r.ASPath...),
		Communities:       append([]uint32(nil), r.Communities...),
		LargeCommunities:  append([]LargeCommunity(nil), r.LargeCommunities...),
		PeerASN:           r.PeerASN,
		PeerAddress:       r.PeerAddress,
		PeerDistinguisher: r.PeerDistinguisher,
		PostPolicy:        r.PostPolicy,
	}
}

func (m routeMeta) empty() bool {
	return len(m.ASPath) == 0 &&
		len(m.Communities) == 0 &&
		len(m.LargeCommunities) == 0 &&
		m.PeerASN == 0 &&
		!m.PeerAddress.IsValid() &&
		m.PeerDistinguisher == 0 &&
		!m.PostPolicy
}

func (m routeMeta) clone() routeMeta {
	m.ASPath = append([]uint32(nil), m.ASPath...)
	m.Communities = append([]uint32(nil), m.Communities...)
	m.LargeCommunities = append([]LargeCommunity(nil), m.LargeCommunities...)
	return m
}

func (m routeMeta) key() routeMetaKey {
	return routeMetaKey{
		ASPath:            encodeUint32s(m.ASPath),
		Communities:       encodeUint32s(m.Communities),
		LargeCommunities:  encodeLargeCommunities(m.LargeCommunities),
		PeerASN:           m.PeerASN,
		PeerAddress:       m.PeerAddress,
		PeerDistinguisher: m.PeerDistinguisher,
		PostPolicy:        m.PostPolicy,
	}
}

func flattenASPath(path []bgp.AsPathParamInterface) []uint32 {
	var out []uint32
	for _, seg := range path {
		asns := seg.GetAS()
		out = append(out, asns...)
	}
	return out
}

// originASN returns the origin of an AS path, the last ASN of the last
// segment when that segment is a sequence, and 0 with the set flag raised
// when the path ends in an AS_SET, where the origin is ambiguous
func originASN(path []bgp.AsPathParamInterface) (uint32, bool) {
	if len(path) == 0 {
		return 0, false
	}
	last := path[len(path)-1]
	switch last.GetType() {
	case bgp.BGP_ASPATH_ATTR_TYPE_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
		return 0, true
	}
	asns := last.GetAS()
	if len(asns) == 0 {
		return 0, false
	}
	return asns[len(asns)-1], false
}

func prefixFromNLRI(nlri bgp.AddrPrefixInterface) (netip.Prefix, bool) {
	if prefix, ok := prefixFromFlat(nlri.Flat()); ok {
		return prefix, true
	}

	prefix, err := netip.ParsePrefix(nlri.String())
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
}

func prefixFromFlat(flat map[string]string) (netip.Prefix, bool) {
	pfx, ok := flat["Prefix"]
	if !ok || pfx == "" {
		return netip.Prefix{}, false
	}

	bits, ok := flat["PrefixLen"]
	if !ok || bits == "" {
		return netip.Prefix{}, false
	}

	n, err := strconv.Atoi(bits)
	if err != nil {
		return netip.Prefix{}, false
	}

	addr, err := netip.ParseAddr(pfx)
	if err != nil {
		return netip.Prefix{}, false
	}

	return netip.PrefixFrom(addr.Unmap(), n).Masked(), true
}

func insertValue(v4, v6 *bart.Table[routeValue], value routeValue) {
	if value.Prefix.Addr().Is4() {
		v4.Insert(value.Prefix, value)
		return
	}
	v6.Insert(value.Prefix, value)
}

func deletePrefix(v4, v6 *bart.Table[routeValue], prefix netip.Prefix) {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		v4.Delete(prefix)
		return
	}
	v6.Delete(prefix)
}

func lookupTable(v4, v6 *bart.Table[routeValue], addr netip.Addr) (routeValue, bool) {
	if addr.Is4() {
		return v4.Lookup(addr)
	}
	return v6.Lookup(addr)
}

func encodeUint32s(values []uint32) string {
	if len(values) == 0 {
		return ""
	}

	var b strings.Builder
	for _, value := range values {
		b.WriteString(strconv.FormatUint(uint64(value), 10))
		b.WriteByte(',')
	}
	return b.String()
}

func encodeLargeCommunities(values []LargeCommunity) string {
	if len(values) == 0 {
		return ""
	}

	var b strings.Builder
	for _, value := range values {
		b.WriteString(strconv.FormatUint(uint64(value.GlobalAdmin), 10))
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(uint64(value.LocalData1), 10))
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(uint64(value.LocalData2), 10))
		b.WriteByte(',')
	}
	return b.String()
}
