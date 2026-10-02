package rib

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gaissmai/bart"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
)

const (
	// bmpScannerMaxBuf caps BMP message size, very big and prob not necessary (just in case)
	bmpScannerMaxBuf = 1 << 20
	// removeChunk is how many routes RemovePeer withdraws per hold of the
	// write lock, the collector looks labels up under its own lock
	removeChunk = 1024
	// maxSessions bounds the BMP sessions open at once, a router runs one
	// or a few and every session holds a goroutine and its read buffer
	maxSessions = 16
	// maxPathLen and maxCommunities bound what a route keeps of its
	// attributes, labels need only the origin, which the route keeps apart,
	// and a lookup shows the leading part of a longer list on a route
	// marked truncated, a route whose attributes no other route shares then
	// holds about 3 KiB of heap however long they are
	maxPathLen     = 32
	maxCommunities = 32
	// maxRoutes bounds the routes the RIB keeps, six views of a full table
	// of about 1.25M prefixes fit, and maxViews bounds the views
	maxRoutes = 1 << 23
	maxViews  = 1024
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
	// PathID tells apart the paths a view holds for one prefix when the
	// session negotiated ADD-PATH, it is 0 otherwise
	PathID uint32
	// Truncated marks a route of the table whose AS path, communities or
	// large communities were longer than it keeps, they then hold only
	// their leading values, see maxPathLen
	Truncated bool
}

// Peer returns the view this route belongs to
func (r Route) Peer() Peer {
	return Peer{Address: r.PeerAddress, Distinguisher: r.PeerDistinguisher, PostPolicy: r.PostPolicy}
}

// view holds the routes of one view, keyed by prefix in a trie of its own
// with ADD-PATH a view holds several paths for a prefix, routes keeps the
// one with the lowest path id, which the view serves, and more the others
type view struct {
	peer   Peer
	routes bart.Table[viewRoute]
	more   map[netip.Prefix][]viewRoute
}

// viewRoute is what a view keeps of a route, the prefix is its trie key and
// the rest of the route sits in the interned metadata
type viewRoute struct {
	metaID      uint64
	pathID      uint32
	originASN   uint32
	originASSet bool
}

// bestRoute is the route the table serves for a prefix
// it copies the origin of the winning view's route so labels read one trie,
// and views counts the views that hold the prefix so the last withdraw
// deletes it without searching the views
type bestRoute struct {
	view        *view
	originASN   uint32
	views       uint32
	bits        uint8
	originASSet bool
}

type routeMeta struct {
	ASPath            []uint32
	Communities       []uint32
	LargeCommunities  []LargeCommunity
	PeerASN           uint32
	PeerAddress       netip.Addr
	PeerDistinguisher uint64
	PostPolicy        bool
	Truncated         bool
}

type routeMetaKey struct {
	ASPath            string
	Communities       string
	LargeCommunities  string
	PeerASN           uint32
	PeerAddress       netip.Addr
	PeerDistinguisher uint64
	PostPolicy        bool
	Truncated         bool
}

type routeMetaState struct {
	key  routeMetaKey
	meta routeMeta
	refs int
}

// Update is a batch of RIB changes
// Reach routes carry their own peer, Withdraw paths are withdrawn from Peer,
// or from every peer when Peer is the zero value
type Update struct {
	Peer     Peer
	Reach    []Route
	Withdraw []Withdrawal
}

// Withdrawal names the path a withdraw removes, PathID is the ADD-PATH path
// id and 0 when the session did not negotiate ADD-PATH
type Withdrawal struct {
	Prefix netip.Prefix
	PathID uint32
}

// Summary counts what the table holds
type Summary struct {
	PrefixesV4 int
	PrefixesV6 int
	Routes     int
	Peers      int
}

// Table is a longest-prefix-match routing table
// every view keeps its routes in a trie of its own and best keeps the route
// that wins per prefix, so a prefix that one view announces costs an entry
// in two tries and no map, and removing a view walks only its own routes
type Table struct {
	// writeMu serializes the writers, RemovePeer releases mu between chunks
	// for the readers but no writer may run then, best still counts the
	// routes of the view it takes apart
	writeMu sync.Mutex
	mu      sync.RWMutex
	best    bart.Table[bestRoute]
	// views holds the views with at least one route, order holds the same
	// views by preference, see betterPeer
	views    map[Peer]*view
	order    []*view
	routes   int
	faults   atomic.Uint64
	metas    map[uint64]*routeMetaState
	metaKeys map[routeMetaKey]uint64
	nextMeta uint64

	// maxRoutes and maxViews bound the routes and views a speaker can make
	// the table hold, a route past either is counted in rejected and
	// dropped, limitLogged is when that was last logged
	maxRoutes   int
	maxViews    int
	rejected    atomic.Uint64
	limitLogged time.Time
}

// NewTable creates an empty RIB table
func NewTable() *Table {
	return &Table{
		views:     make(map[Peer]*view),
		metas:     make(map[uint64]*routeMetaState),
		metaKeys:  make(map[routeMetaKey]uint64),
		nextMeta:  1,
		maxRoutes: maxRoutes,
		maxViews:  maxViews,
	}
}

// Apply applies a batch of route updates
func (t *Table) Apply(update Update) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, w := range update.Withdraw {
		prefix := w.Prefix.Masked()
		if update.Peer == (Peer{}) {
			// deleteRoute may drop the view from the map, which a range
			// over it allows
			for _, v := range t.views {
				t.deleteRoute(prefix, w.PathID, v)
			}
			continue
		}
		if v := t.views[update.Peer]; v != nil {
			t.deleteRoute(prefix, w.PathID, v)
		}
	}
	for _, route := range update.Reach {
		t.insertRoute(route)
	}
}

// RemovePeer withdraws every route learned from peer
// the view leaves the table before the walk over its routes, so withdrawn
// picks the next best among the other views, and the walk releases mu
// every removeChunk routes while it keeps writeMu, readers then wait for
// one chunk and not for a whole table, and until the walk gets to a prefix
// they still find the view's route for it through best
func (t *Table) RemovePeer(peer Peer) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.mu.Lock()
	defer t.mu.Unlock()

	v := t.views[peer]
	if v == nil {
		return
	}
	// out of order first, so withdrawn picks the next best among the others
	t.dropView(v)
	n := 0
	for prefix, value := range v.routes.All() {
		t.releaseMeta(value.metaID)
		t.routes--
		for _, path := range v.more[prefix] {
			t.releaseMeta(path.metaID)
			t.routes--
		}
		t.withdrawn(prefix, v)
		if n++; n%removeChunk == 0 {
			t.mu.Unlock()
			t.mu.Lock()
		}
	}
}

// RemovePeerViews withdraws every route learned from the pre and the post
// policy view of peer's address and distinguisher
// peer up and peer down concern the BGP session, which feeds both views, and
// a speaker need not set the L flag of their per peer header to match the
// routes, BIRD always sends them as pre policy
func (t *Table) RemovePeerViews(peer Peer) {
	for _, post := range []bool{false, true} {
		peer.PostPolicy = post
		t.RemovePeer(peer)
	}
}

// Lookup returns the best matching route for addr
func (t *Table) Lookup(addr netip.Addr) (Route, bool) {
	addr = addr.Unmap()

	t.mu.RLock()
	defer t.mu.RUnlock()

	best, ok := t.best.Lookup(addr)
	if !ok {
		return Route{}, false
	}
	// the winning view holds every prefix best credits to it
	prefix := netip.PrefixFrom(addr, int(best.bits)).Masked()
	value, ok := best.view.routes.Get(prefix)
	if !ok {
		t.fault("best credits a view with a prefix it does not hold", prefix)
		return Route{}, false
	}
	return t.route(prefix, value)
}

// Enrich returns only the labels Prometheus needs
// a default route labels nothing, its origin is the upstream that carries
// the traffic and not the network that owns the address, so the next
// backend gets to label it
func (t *Table) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	return t.labels(src), t.labels(dst)
}

func (t *Table) labels(addr netip.Addr) collector.Labels {
	addr = addr.Unmap()

	t.mu.RLock()
	defer t.mu.RUnlock()

	best, ok := t.best.Lookup(addr)
	if !ok || best.bits == 0 {
		return collector.Labels{}
	}
	return collector.Labels{ASN: best.originASN}
}

// Summary counts the prefixes, routes and peers in the table
func (t *Table) Summary() Summary {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return Summary{
		PrefixesV4: t.best.Size4(),
		PrefixesV6: t.best.Size6(),
		Routes:     t.routes,
		Peers:      len(t.views),
	}
}

// Peers lists the views with at least one route
func (t *Table) Peers() []Peer {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]Peer, 0, len(t.views))
	for peer := range t.views {
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
	// failed closes when accept stopped on an error that is not temporary,
	// which failure holds
	failed  chan struct{}
	failure error
	// maxSessions bounds the sessions open at once, limitLogged is when the
	// last session over it was logged, both under connsMu
	maxSessions      int
	limitLogged      time.Time
	parseErrors      atomic.Uint64
	sessionsRejected atomic.Uint64
}

func newServer(ln net.Listener) *Server {
	return &Server{
		listener:    ln,
		table:       NewTable(),
		done:        make(chan struct{}),
		failed:      make(chan struct{}),
		conns:       make(map[net.Conn]struct{}),
		maxSessions: maxSessions,
	}
}

// Stats counts what the BMP listener saw since it started
type Stats struct {
	// Sessions is the number of BMP sessions open now
	Sessions int
	// SessionsRejected counts the connections closed right after accept
	// because the most sessions rfm serves at once were open
	SessionsRejected uint64
	// ParseErrors counts the messages that did not parse in full, the
	// usable part of some of them still applies, and the updates a session
	// dropped because it does not know the capabilities of their peer
	ParseErrors uint64
	// RoutesRejected counts the routes the RIB did not store because it
	// held the most routes or views it keeps
	RoutesRejected uint64
	// Inconsistencies counts the lookups and updates that found the RIB
	// contradicting itself, a bug in rfm, see Table.fault
	Inconsistencies uint64
}

// Stats returns the counters of the BMP listener
func (s *Server) Stats() Stats {
	s.connsMu.Lock()
	sessions := len(s.conns)
	s.connsMu.Unlock()

	return Stats{
		Sessions:         sessions,
		SessionsRejected: s.sessionsRejected.Load(),
		ParseErrors:      s.parseErrors.Load(),
		RoutesRejected:   s.table.rejected.Load(),
		Inconsistencies:  s.table.faults.Load(),
	}
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

	s := newServer(ln)
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

// Wait returns ctx.Err() once ctx is done, or the error that stopped the
// listener, an accept error that is not temporary, the open sessions go on
// until Close
func (s *Server) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.failed:
		return s.failure
	}
}

func (s *Server) accept() {
	defer s.wg.Done()

	var delay time.Duration
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.isClosing() {
				return
			}
			// accept still marks fd exhaustion with the deprecated
			// Temporary, any other error stops the listener for Wait to
			// report
			var te interface{ Temporary() bool }
			if !errors.As(err, &te) || !te.Temporary() {
				s.failure = fmt.Errorf("accept bmp connection: %w", err)
				close(s.failed)
				log.Error("bmp listener stopped", "err", err)
				return
			}
			// a listener out of file descriptors fails every accept at
			// once, so wait between tries as net/http does
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			log.Warn("bmp accept", "err", err, "retry_in", delay)
			select {
			case <-s.done:
				return
			case <-time.After(delay):
			}
			continue
		}
		delay = 0

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

	// the scanner starts small and doubles its buffer up to the largest
	// message the session sends, an idle session holds 4 KiB
	scanner := bufio.NewScanner(conn)
	scanner.Split(splitBMP)
	scanner.Buffer(nil, bmpScannerMaxBuf)

	var messages int
	var changes int
	var parseErrors int
	var appliedLogged bool
	seenTypes := make(map[uint8]struct{})
	peers := make(map[Peer]struct{})

	// addPath holds the decode options of the peers whose peer up shows
	// that they send ADD-PATH to the monitored router, and nil for those
	// whose peer up did not parse, keyed by address and distinguisher, the
	// policy views of a peer share its session
	// it holds at most maxViews peers, overflow records that a peer up
	// came past them
	addPath := make(map[Peer][]*bgp.MarshallingOption)
	var overflow bool
	options := func(h bmp.BMPPeerHeader) []*bgp.MarshallingOption {
		peer := peerFromHeader(h)
		peer.PostPolicy = false
		return addPath[peer]
	}
	// undecodable reports whether the session cannot read the updates of
	// the peer of h, a peer up that did not parse leaves the capabilities
	// of the peer unknown, and without them ADD-PATH path ids read as
	// prefixes, after an overflow any peer the session does not hold may
	// send them
	undecodable := func(h bmp.BMPPeerHeader) bool {
		peer := peerFromHeader(h)
		peer.PostPolicy = false
		opts, held := addPath[peer]
		return held && opts == nil || !held && overflow
	}

	for scanner.Scan() {
		messages++

		msg, err := bmp.ParseBMPMessageWithOptions(scanner.Bytes(), options)
		if msg != nil && msg.Header.Type == bmp.BMP_MSG_ROUTE_MONITORING && undecodable(msg.PeerHeader) {
			msg, err = nil, fmt.Errorf("%w, peer %s", errUndecodable, msg.PeerHeader.PeerAddress)
		}
		var treatAsWithdraw bool
		if err != nil {
			s.parseErrors.Add(1)
			if parseErrors++; parseErrors == 1 {
				log.Error("parse bmp message", "remote", conn.RemoteAddr(), "err", err)
			}
			if msg, treatAsWithdraw = salvage(scanner.Bytes(), msg, err); msg == nil {
				continue
			}
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
			s.table.RemovePeerViews(peer)
			peer.PostPolicy = false
			delete(addPath, peer)
			var opts []*bgp.MarshallingOption
			up, parsed := msg.Body.(*bmp.BMPPeerUpNotification)
			if parsed {
				opts = addPathOptions(up)
			}
			switch {
			case parsed && opts == nil:
				// a peer without ADD-PATH needs no entry
			case len(addPath) < maxViews:
				addPath[peer] = opts
			case !overflow:
				overflow = true
				log.Error("bmp session past its add-path peer limit, dropping the updates of the peers it does not track", "remote", conn.RemoteAddr(), "peer", peer.Address, "limit", maxViews)
			}
			log.Info("bmp peer up", "remote", conn.RemoteAddr(), "peer", peer.Address, "add_path", opts != nil, "capabilities_known", parsed)
			continue
		case bmp.BMP_MSG_PEER_DOWN_NOTIFICATION:
			peer := peerFromHeader(msg.PeerHeader)
			s.table.RemovePeerViews(peer)
			for _, post := range []bool{false, true} {
				peer.PostPolicy = post
				delete(peers, peer)
			}
			peer.PostPolicy = false
			delete(addPath, peer)
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
		if treatAsWithdraw {
			for _, route := range update.Reach {
				update.Withdraw = append(update.Withdraw, Withdrawal{Prefix: route.Prefix, PathID: route.PathID})
			}
			update.Reach = nil
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

	err := scanner.Err()
	if errors.Is(err, errBMPVersion) || errors.Is(err, errBMPLength) {
		// a header no message can have ends the session, and it is a
		// message that did not parse
		s.parseErrors.Add(1)
		parseErrors++
	}
	if err != nil && !s.isClosing() {
		log.Error("read bmp stream", "remote", conn.RemoteAddr(), "err", err)
	}

	log.Info(
		"bmp session closed",
		"remote", conn.RemoteAddr(),
		"messages", messages,
		"parse_errors", parseErrors,
		"changes", changes,
		"peers", len(peers),
	)
}

// salvage returns what a message that failed to parse still offers, and
// whether the routes of an update must be withdrawn instead of installed
// RFC 7606 has a receiver discard a malformed attribute that does not
// change the route, or treat the update as a withdraw of every route it
// carries, gobgp returns the update it decoded with an error that says
// which, any other update error leaves nothing to trust
// gobgp returns nothing when the body of a peer up or peer down does not
// parse, but the per peer header in front of it still names the peer, and
// that is all those two need
func salvage(data []byte, msg *bmp.BMPMessage, err error) (*bmp.BMPMessage, bool) {
	if len(data) >= bmp.BMP_HEADER_SIZE+bmp.BMP_PEER_HEADER_SIZE && data[0] == bmp.BMP_VERSION {
		switch typ := data[5]; typ {
		case bmp.BMP_MSG_PEER_UP_NOTIFICATION, bmp.BMP_MSG_PEER_DOWN_NOTIFICATION:
			out := &bmp.BMPMessage{Header: bmp.BMPHeader{Version: bmp.BMP_VERSION, Type: typ}}
			if out.PeerHeader.DecodeFromBytes(data[bmp.BMP_HEADER_SIZE:]) != nil {
				return nil, false
			}
			return out, false
		}
	}

	var msgErr *bgp.MessageError
	if msg == nil || msg.Header.Type != bmp.BMP_MSG_ROUTE_MONITORING || !errors.As(err, &msgErr) {
		return nil, false
	}
	switch msgErr.ErrorHandling {
	case bgp.ERROR_HANDLING_ATTRIBUTE_DISCARD:
		return msg, false
	case bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW:
		return msg, true
	}
	return nil, false
}

// errUndecodable is the parse error of an update whose peer the session
// cannot decode, see undecodable
var errUndecodable = errors.New("bmp update of a peer whose capabilities are unknown")

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
	if len(s.conns) >= s.maxSessions {
		_ = conn.Close()
		rejected := s.sessionsRejected.Add(1)
		if every(&s.limitLogged, time.Minute) {
			log.Warn("bmp session limit reached, closing new sessions", "remote", conn.RemoteAddr(), "limit", s.maxSessions, "rejected", rejected)
		}
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

// every reports whether interval passed since last and then moves last to
// now, which keeps a log line about a limit to one per interval
// the caller holds the lock that guards last
func every(last *time.Time, interval time.Duration) bool {
	now := time.Now()
	if !last.IsZero() && now.Sub(*last) < interval {
		return false
	}
	*last = now
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

	attrs := routeAttrs(updateMsg.PathAttributes, msg.PeerHeader.Flags&bmp.BMP_PEER_FLAG_TWO_AS != 0)

	out := Update{Peer: peerFromHeader(msg.PeerHeader)}
	reach := func(nlri bgp.AddrPrefixInterface) {
		if prefix, ok := prefixFromNLRI(nlri); ok {
			route := attrs.route(prefix, msg.PeerHeader)
			route.PathID = nlri.PathIdentifier()
			out.Reach = append(out.Reach, route)
		}
	}
	withdraw := func(nlri bgp.AddrPrefixInterface) {
		if prefix, ok := prefixFromNLRI(nlri); ok {
			out.Withdraw = append(out.Withdraw, Withdrawal{Prefix: prefix, PathID: nlri.PathIdentifier()})
		}
	}

	for _, nlri := range updateMsg.WithdrawnRoutes {
		withdraw(nlri)
	}
	for _, nlri := range updateMsg.NLRI {
		reach(nlri)
	}
	for _, attr := range updateMsg.PathAttributes {
		if otherFamily(attr) {
			continue
		}
		switch a := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			for _, nlri := range a.Value {
				reach(nlri)
			}
		case *bgp.PathAttributeMpUnreachNLRI:
			for _, nlri := range a.Value {
				withdraw(nlri)
			}
		}
	}

	return out, true
}

// addPathOptions returns the options that decode what the monitored router
// receives from the peer of a peer up notification, RFC 7911 section 4 has
// a family carry path ids when the router's OPEN, the sent one, offered to
// receive them and the peer's OPEN, the received one, offered to send them
func addPathOptions(up *bmp.BMPPeerUpNotification) []*bgp.MarshallingOption {
	sent := addPathModes(up.SentOpenMsg)
	received := addPathModes(up.ReceivedOpenMsg)

	var modes map[bgp.RouteFamily]bgp.BGPAddPathMode
	for family, mode := range sent {
		if mode&bgp.BGP_ADD_PATH_RECEIVE != 0 && received[family]&bgp.BGP_ADD_PATH_SEND != 0 {
			if modes == nil {
				modes = make(map[bgp.RouteFamily]bgp.BGPAddPathMode)
			}
			modes[family] = bgp.BGP_ADD_PATH_RECEIVE
		}
	}
	if modes == nil {
		return nil
	}
	return []*bgp.MarshallingOption{{AddPath: modes}}
}

// addPathModes collects the ADD-PATH capability of an OPEN message by family
func addPathModes(msg *bgp.BGPMessage) map[bgp.RouteFamily]bgp.BGPAddPathMode {
	if msg == nil {
		return nil
	}
	open, ok := msg.Body.(*bgp.BGPOpen)
	if !ok {
		return nil
	}

	modes := make(map[bgp.RouteFamily]bgp.BGPAddPathMode)
	for _, param := range open.OptParams {
		caps, ok := param.(*bgp.OptionParameterCapability)
		if !ok {
			continue
		}
		for _, c := range caps.Capability {
			if addPath, ok := c.(*bgp.CapAddPath); ok {
				for _, tuple := range addPath.Tuples {
					modes[tuple.RouteFamily] = tuple.Mode
				}
			}
		}
	}
	return modes
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

// insertRoute stores route in the view of its peer and updates best
// it must be called with mu held
func (t *Table) insertRoute(route Route) {
	prefix := route.Prefix.Masked()
	if !prefix.IsValid() {
		t.fault("a route without a valid prefix", route.Prefix)
		return
	}

	v := t.views[route.Peer()]
	var head viewRoute
	var held bool
	if v != nil {
		head, held = v.routes.Get(prefix)
	}
	var paths []viewRoute
	i := -1
	if held && head.pathID != route.PathID {
		paths = v.more[prefix]
		i = slices.IndexFunc(paths, func(p viewRoute) bool { return p.pathID == route.PathID })
	}
	// a route that replaces the same path takes no room
	if (!held || (head.pathID != route.PathID && i < 0)) && !t.admit(v == nil) {
		return
	}
	if v == nil {
		v = &view{peer: route.Peer()}
		t.addView(v)
	}

	// intern before the release, a route that keeps its metadata then
	// never drops the last reference to it
	value := viewRoute{
		metaID:      t.internMeta(route.meta()),
		pathID:      route.PathID,
		originASN:   route.OriginASN,
		originASSet: route.OriginASSet,
	}
	switch {
	case !held:
		v.routes.Insert(prefix, value)
		t.routes++
		t.offered(prefix, v, value, true)
	case head.pathID == value.pathID:
		v.routes.Insert(prefix, value)
		t.releaseMeta(head.metaID)
		t.offered(prefix, v, value, false)
	case i >= 0:
		t.releaseMeta(paths[i].metaID)
		paths[i] = value
	case value.pathID < head.pathID:
		// the view serves its lowest path id whatever order the paths
		// arrive in
		v.setMore(prefix, append(paths, head))
		v.routes.Insert(prefix, value)
		t.routes++
		t.offered(prefix, v, value, false)
	default:
		v.setMore(prefix, append(paths, value))
		t.routes++
	}
}

// admit reports whether the table has room for one more route, and for
// one more view when newView is set, a route turned away is counted and
// logged once a minute at most
// it must be called with mu held
func (t *Table) admit(newView bool) bool {
	var limit string
	switch {
	case newView && len(t.views) >= t.maxViews:
		limit = "views"
	case t.routes >= t.maxRoutes:
		limit = "routes"
	default:
		return true
	}
	rejected := t.rejected.Add(1)
	if every(&t.limitLogged, time.Minute) {
		log.Warn("rib limit reached, dropping routes", "limit", limit, "routes", t.routes, "views", len(t.views), "rejected", rejected)
	}
	return false
}

// deleteRoute drops path pathID of view v for prefix and updates best
// it must be called with mu held
func (t *Table) deleteRoute(prefix netip.Prefix, pathID uint32, v *view) {
	head, ok := v.routes.Get(prefix)
	if !ok {
		return
	}
	paths := v.more[prefix]
	if head.pathID != pathID {
		i := slices.IndexFunc(paths, func(p viewRoute) bool { return p.pathID == pathID })
		if i < 0 {
			return
		}
		t.releaseMeta(paths[i].metaID)
		t.routes--
		v.setMore(prefix, slices.Delete(paths, i, i+1))
		return
	}

	t.releaseMeta(head.metaID)
	t.routes--
	if len(paths) > 0 {
		// the next lowest path id takes over
		i := 0
		for j, p := range paths {
			if p.pathID < paths[i].pathID {
				i = j
			}
		}
		next := paths[i]
		v.setMore(prefix, slices.Delete(paths, i, i+1))
		v.routes.Insert(prefix, next)
		t.offered(prefix, v, next, false)
		return
	}
	v.routes.Delete(prefix)
	if v.routes.Size() == 0 {
		t.dropView(v)
	}
	t.withdrawn(prefix, v)
}

// setMore stores the other paths of prefix, dropping the entry when none
// are left
func (v *view) setMore(prefix netip.Prefix, paths []viewRoute) {
	if len(paths) == 0 {
		delete(v.more, prefix)
		return
	}
	if v.more == nil {
		v.more = make(map[netip.Prefix][]viewRoute)
	}
	v.more[prefix] = paths
}

// offered updates best after view v announced value for prefix, added says
// that v did not hold prefix before
// it must be called with mu held
func (t *Table) offered(prefix netip.Prefix, v *view, value viewRoute, added bool) {
	best, ok := t.best.Get(prefix)
	if !ok {
		t.best.Insert(prefix, bestRoute{
			view:        v,
			originASN:   value.originASN,
			views:       1,
			bits:        uint8(prefix.Bits()),
			originASSet: value.originASSet,
		})
		return
	}
	if added {
		best.views++
	}
	if best.view == v || betterPeer(v.peer, best.view.peer) {
		best.view, best.originASN, best.originASSet = v, value.originASN, value.originASSet
	}
	t.best.Insert(prefix, best)
}

// withdrawn updates best after view v gave up prefix, when v won it the
// first view in order that still holds prefix takes over
// v may still hold prefix in its trie, so it is skipped
// it must be called with mu held
func (t *Table) withdrawn(prefix netip.Prefix, v *view) {
	best, ok := t.best.Get(prefix)
	if !ok {
		t.fault("a view gave up a prefix best does not hold", prefix)
		return
	}
	if best.views--; best.views == 0 {
		t.best.Delete(prefix)
		return
	}
	if best.view == v {
		for _, w := range t.order {
			if value, ok := w.routes.Get(prefix); ok && w != v {
				best.view, best.originASN, best.originASSet = w, value.originASN, value.originASSet
				break
			}
		}
	}
	t.best.Insert(prefix, best)
}

// fault counts a lookup or an update that found the table contradicting
// itself, a bug in rfm, the lookup then finds no route and the update skips
// what it would change, lookups hold mu for reading only, so the count is
// atomic and only the first fault is logged
func (t *Table) fault(what string, prefix netip.Prefix) {
	if t.faults.Add(1) == 1 {
		log.Error("rib table inconsistent, a bug in rfm", "fault", what, "prefix", prefix)
	}
}

// addView adds v to the views and keeps order sorted by preference
// it must be called with mu held
func (t *Table) addView(v *view) {
	t.views[v.peer] = v
	i, _ := slices.BinarySearchFunc(t.order, v, func(a, b *view) int {
		if betterPeer(a.peer, b.peer) {
			return -1
		}
		return 1
	})
	t.order = slices.Insert(t.order, i, v)
}

// dropView removes v from the views and from order
// it must be called with mu held
func (t *Table) dropView(v *view) {
	delete(t.views, v.peer)
	if i := slices.Index(t.order, v); i >= 0 {
		t.order = slices.Delete(t.order, i, i+1)
	}
}

// betterPeer orders the views, a post policy view wins over a pre policy
// one, then the lowest peer address and distinguisher, which keeps the
// choice stable across updates
func betterPeer(a, b Peer) bool {
	if a.PostPolicy != b.PostPolicy {
		return a.PostPolicy
	}
	if c := a.Address.Compare(b.Address); c != 0 {
		return c < 0
	}
	return a.Distinguisher < b.Distinguisher
}

func (t *Table) route(prefix netip.Prefix, value viewRoute) (Route, bool) {
	route := Route{
		Prefix:      prefix,
		OriginASN:   value.originASN,
		OriginASSet: value.originASSet,
		PathID:      value.pathID,
	}
	if value.metaID == 0 {
		return route, true
	}

	state, ok := t.metas[value.metaID]
	if !ok {
		t.fault("a route refers to metadata the table released", prefix)
		return Route{}, false
	}

	routeMeta := state.meta.clone()
	route.ASPath = routeMeta.ASPath
	route.Communities = routeMeta.Communities
	route.LargeCommunities = routeMeta.LargeCommunities
	route.PeerASN = routeMeta.PeerASN
	route.PeerAddress = routeMeta.PeerAddress
	route.PeerDistinguisher = routeMeta.PeerDistinguisher
	route.PostPolicy = routeMeta.PostPolicy
	route.Truncated = routeMeta.Truncated
	return route, true
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

// routeAttrs decodes the attributes rfm keeps from a route
// twoByteAS is the A flag of the per peer header, the route then comes in
// the legacy format whose AS_PATH holds AS_TRANS for every 4-byte ASN, and
// the real ASNs are in AS4_PATH
func routeAttrs(pathAttrs []bgp.PathAttributeInterface, twoByteAS bool) attrs {
	var out attrs
	var asPath []bgp.AsPathParamInterface
	var as4Path []*bgp.As4PathParam
	var aggregator *bgp.PathAttributeAggregator
	var as4Aggregator bool

	for _, attr := range pathAttrs {
		switch a := attr.(type) {
		case *bgp.PathAttributeAsPath:
			asPath = a.Value
		case *bgp.PathAttributeAs4Path:
			as4Path = a.Value
		case *bgp.PathAttributeAggregator:
			aggregator = a
		case *bgp.PathAttributeAs4Aggregator:
			as4Aggregator = true
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

	// RFC 6793 section 4.2.3, an aggregator that is not AS_TRANS next to
	// AS4_AGGREGATOR means a 2-byte speaker aggregated the route after
	// AS4_PATH was written, so AS4_PATH no longer describes it
	stale := aggregator != nil && as4Aggregator && aggregator.Value.AS != bgp.AS_TRANS
	if twoByteAS && len(as4Path) > 0 && !stale {
		asPath = mergeAS4Path(asPath, as4Path)
	}
	out.asPath = flattenASPath(asPath)
	out.originASN, out.originASSet = originASN(asPath)

	return out
}

// mergeAS4Path rebuilds the path of a route from the legacy format as RFC
// 6793 section 4.2.3 does, AS4_PATH holds the tail of the path and AS_PATH
// gives the leading ASNs that AS4_PATH lacks together with confederation
// segments next to them, an AS4_PATH that counts more ASNs than AS_PATH is
// ignored
func mergeAS4Path(asPath []bgp.AsPathParamInterface, as4Path []*bgp.As4PathParam) []bgp.AsPathParamInterface {
	var tail []bgp.AsPathParamInterface
	for _, seg := range as4Path {
		// AS4_PATH never carries confederation segments, RFC 6793 section 6
		// has a receiver discard them
		if isConfed(seg) {
			continue
		}
		tail = append(tail, seg)
	}

	need := pathLen(asPath) - pathLen(tail)
	if need < 0 {
		return asPath
	}

	var out []bgp.AsPathParamInterface
	for _, seg := range asPath {
		switch {
		case isConfed(seg):
			// every segment before it was taken, so it leads the path or
			// follows a taken segment and goes along
		case need == 0:
			return append(out, tail...)
		case seg.GetType() == bgp.BGP_ASPATH_ATTR_TYPE_SEQ && seg.ASLen() > need:
			seg = bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, seg.GetAS()[:need])
			need = 0
		default:
			need -= seg.ASLen()
		}
		out = append(out, seg)
	}
	return append(out, tail...)
}

// pathLen counts the ASNs of a path for route selection, an AS_SET counts
// as one and confederation segments count as none
func pathLen(path []bgp.AsPathParamInterface) int {
	var n int
	for _, seg := range path {
		n += seg.ASLen()
	}
	return n
}

func isConfed(seg bgp.AsPathParamInterface) bool {
	switch seg.GetType() {
	case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
		return true
	}
	return false
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

// meta returns what the table keeps of r besides its prefix and origin, the
// leading maxPathLen ASNs of its path and maxCommunities communities and
// large communities each, and whether that cut any of them
func (r Route) meta() routeMeta {
	return routeMeta{
		ASPath:            leading(r.ASPath, maxPathLen),
		Communities:       leading(r.Communities, maxCommunities),
		LargeCommunities:  leading(r.LargeCommunities, maxCommunities),
		PeerASN:           r.PeerASN,
		PeerAddress:       r.PeerAddress,
		PeerDistinguisher: r.PeerDistinguisher,
		PostPolicy:        r.PostPolicy,
		Truncated:         len(r.ASPath) > maxPathLen || len(r.Communities) > maxCommunities || len(r.LargeCommunities) > maxCommunities,
	}
}

// leading returns a copy of at most the first n values of s
func leading[T any](s []T, n int) []T {
	return append([]T(nil), s[:min(len(s), n)]...)
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
		Truncated:         m.Truncated,
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

// otherFamily reports whether attr is an MP_REACH_NLRI or MP_UNREACH_NLRI
// of a family other than ipv4 and ipv6 unicast, gobgp decodes multicast
// NLRI into the types of unicast ones, and a multicast route would replace
// or withdraw the unicast route of its prefix
func otherFamily(attr bgp.PathAttributeInterface) bool {
	var afi uint16
	var safi uint8
	switch a := attr.(type) {
	case *bgp.PathAttributeMpReachNLRI:
		afi, safi = a.AFI, a.SAFI
	case *bgp.PathAttributeMpUnreachNLRI:
		afi, safi = a.AFI, a.SAFI
	default:
		return false
	}
	switch bgp.AfiSafiToRouteFamily(afi, safi) {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		return false
	}
	return true
}

// prefixFromNLRI returns the prefix of a unicast NLRI
// the RIB models the global table, so VPN routes, which belong to a VRF,
// and every other family are skipped, an ipv4 mapped ipv6 prefix stays ipv6
// because unmapping it would leave more prefix bits than address bits
// multicast NLRI come in the types of unicast ones, otherFamily skips them
func prefixFromNLRI(nlri bgp.AddrPrefixInterface) (netip.Prefix, bool) {
	var ip net.IP
	var bits uint8
	switch n := nlri.(type) {
	case *bgp.IPAddrPrefix:
		ip, bits = n.Prefix, n.Length
	case *bgp.IPv6AddrPrefix:
		ip, bits = n.Prefix, n.Length
	default:
		return netip.Prefix{}, false
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	prefix, err := addr.Prefix(int(bits))
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
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
