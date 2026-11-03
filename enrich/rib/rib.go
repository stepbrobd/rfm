package rib

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
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
	// removeChunk is how many routes removePeer withdraws per hold of mu, the
	// collector's read loop waits for labels meanwhile
	removeChunk = 1024
	// maxSessions bounds the BMP sessions open at once, a router runs one
	// or a few and every session holds a goroutine and its read buffer
	maxSessions = 16
	// maxPathLen and maxCommunities bound what a route keeps of its
	// attributes, labels need only the origin, which the route keeps apart,
	// and a lookup shows the leading part of a longer list on a route
	// marked truncated, a route whose attributes no other route shares then
	// holds under 2 KiB of heap however long they are
	maxPathLen     = 32
	maxCommunities = 32
	// maxRoutes bounds the routes the RIB keeps, six views of a full table
	// of about 1.25M prefixes fit, and maxViews bounds the views
	maxRoutes = 1 << 23
	maxViews  = 1024
	// staleGrace is how long an open session of the same speaker, a later
	// one or one already open, has to announce a view again before the
	// routes an ended session left in it go, counted from when the view went
	// stale or the session opened, whichever is later, over twice the 120 s
	// ConnectRetryTime RFC 4271 suggests, so a peer that the restarted
	// speaker connects to again is back in time, and staleSweep is how often
	// the server looks
	staleGrace = 5 * time.Minute
	staleSweep = time.Minute
)

// LargeCommunity is a decoded RFC 8092 large community
type LargeCommunity struct {
	GlobalAdmin uint32
	LocalData1  uint32
	LocalData2  uint32
}

// Peer keys a view, the routes one speaker monitors of one peer before or
// after policy
type Peer struct {
	Speaker       netip.Addr
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
	Speaker           netip.Addr
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
	return Peer{Speaker: r.Speaker, Address: r.PeerAddress, Distinguisher: r.PeerDistinguisher, PostPolicy: r.PostPolicy}
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

// routeMeta is what a route keeps besides its prefix, origin and view
type routeMeta struct {
	ASPath           []uint32
	Communities      []uint32
	LargeCommunities []LargeCommunity
	PeerASN          uint32
	Truncated        bool
}

type routeMetaKey struct {
	ASPath           string
	Communities      string
	LargeCommunities string
	PeerASN          uint32
	Truncated        bool
}

type routeMetaState struct {
	key  routeMetaKey
	meta routeMeta
	refs int
}

// update is a batch of RIB changes
// Reach routes carry their own peer, Withdraw paths are withdrawn from Peer
type update struct {
	Peer     Peer
	Reach    []Route
	Withdraw []withdrawal
}

// withdrawal names the path a withdraw removes, PathID is the ADD-PATH path
// id and 0 when the session did not negotiate ADD-PATH
type withdrawal struct {
	Prefix netip.Prefix
	PathID uint32
}

// Summary counts what the table holds
type Summary struct {
	PrefixesV4 int
	PrefixesV6 int
	Routes     int
	// Peers counts the views with at least one route, see Peer
	Peers int
}

// table keeps the routes of every view in a trie of its own and the route
// that wins each prefix in best, its writers run one at a time under
// Server.viewsMu
type table struct {
	mu   sync.RWMutex
	best bart.Table[bestRoute]
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

func newTable() *table {
	return &table{
		views:     make(map[Peer]*view),
		metas:     make(map[uint64]*routeMetaState),
		metaKeys:  make(map[routeMetaKey]uint64),
		nextMeta:  1,
		maxRoutes: maxRoutes,
		maxViews:  maxViews,
	}
}

func (t *table) apply(u update) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, w := range u.Withdraw {
		if v := t.views[u.Peer]; v != nil {
			t.deleteRoute(w.Prefix.Masked(), w.PathID, v)
		}
	}
	for _, route := range u.Reach {
		t.insertRoute(route)
	}
}

// removePeer withdraws every route of the view peer, releasing mu every
// removeChunk routes for the readers, which find the view's route for a
// prefix through best until the walk gets to it
func (t *table) removePeer(peer Peer) {
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

// removePeerViews withdraws every route learned from the pre and the post
// policy view of peer's address and distinguisher
// peer up and peer down concern the BGP session, which feeds both views, and
// a speaker need not set the L flag of their per peer header to match the
// routes, BIRD always sends them as pre policy
func (t *table) removePeerViews(peer Peer) {
	for _, post := range []bool{false, true} {
		peer.PostPolicy = post
		t.removePeer(peer)
	}
}

// lookup returns the best matching route for addr
func (t *table) lookup(addr netip.Addr) (Route, bool) {
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
	return t.route(prefix, best.view, value)
}

// enrich labels nothing from a default route, its origin is the upstream
// that carries the traffic and not the network that owns the address
func (t *table) enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	return t.labels(src), t.labels(dst)
}

func (t *table) labels(addr netip.Addr) collector.Labels {
	addr = addr.Unmap()

	t.mu.RLock()
	defer t.mu.RUnlock()

	best, ok := t.best.Lookup(addr)
	if !ok || best.bits == 0 {
		return collector.Labels{}
	}
	return collector.Labels{ASN: best.originASN}
}

// summary counts the prefixes and routes in the table and the views that
// hold them
func (t *table) summary() Summary {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return Summary{
		PrefixesV4: t.best.Size4(),
		PrefixesV6: t.best.Size6(),
		Routes:     t.routes,
		Peers:      len(t.views),
	}
}

// holds reports whether the table holds a route of peer
func (t *table) holds(peer Peer) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.views[peer] != nil
}

// Server owns a BMP listener and an in-memory RIB
type Server struct {
	listener net.Listener
	table    *table
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

	// viewsMu guards what ages out the views of ended sessions, and holds
	// off sessions while a stale view goes so none announces it meanwhile
	// sessions are the open sessions, owners the open session that last
	// announced each view, and stale the views whose session ended
	// owners and stale hold only views the table holds, which keeps them
	// within maxViews, and are nil while empty, see release
	viewsMu  sync.Mutex
	sessions map[*session]struct{}
	owners   map[Peer]*session
	stale    map[Peer]time.Time
	// staleGrace overrides the default grace period and clock the time
	// source, for tests
	staleGrace time.Duration
	clock      func() time.Time
}

// session is one BMP connection, its speaker is the remote address, which
// a restarted speaker connects from again
type session struct {
	speaker netip.Addr
	opened  time.Time
}

func (s *Server) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

func (s *Server) grace() time.Duration {
	if s.staleGrace > 0 {
		return s.staleGrace
	}
	return staleGrace
}

// sessionOpened registers a session of the speaker conn connects from
func (s *Server) sessionOpened(conn net.Conn) *session {
	sess := &session{opened: s.now()}
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		sess.speaker = addr.AddrPort().Addr().Unmap()
	}

	s.viewsMu.Lock()
	defer s.viewsMu.Unlock()

	if s.sessions == nil {
		s.sessions = make(map[*session]struct{})
	}
	s.sessions[sess] = struct{}{}
	return sess
}

// apply applies update and, while the table holds its view, records that
// sess announces the view, which makes it current again
// a view the update emptied or the table turned away has nothing to age
// out, and an update without routes, such as an End-of-RIB marker, changes
// nothing, the update runs under viewsMu so purgeStale cannot remove the
// view between the update and the record
func (s *Server) apply(sess *session, u update) {
	if len(u.Reach) == 0 && len(u.Withdraw) == 0 {
		return
	}

	s.viewsMu.Lock()
	defer s.viewsMu.Unlock()

	s.table.apply(u)
	view := u.Peer
	if s.table.holds(view) {
		if s.owners == nil {
			s.owners = make(map[Peer]*session)
		}
		s.owners[view] = sess
	} else {
		delete(s.owners, view)
		s.owners = release(s.owners)
	}
	delete(s.stale, view)
	s.stale = release(s.stale)
}

// release returns nil for an empty map, since a map keeps the room of the
// most entries it held, and a nil map reads and deletes as an empty one
func release[V any](m map[Peer]V) map[Peer]V {
	if len(m) == 0 {
		return nil
	}
	return m
}

// peerChanged withdraws both views of peer on peer up and peer down, after
// a peer up the speaker announces them again, so neither ages out
func (s *Server) peerChanged(peer Peer) {
	s.viewsMu.Lock()
	defer s.viewsMu.Unlock()

	s.table.removePeerViews(peer)
	for _, post := range []bool{false, true} {
		peer.PostPolicy = post
		delete(s.owners, peer)
		delete(s.stale, peer)
	}
	s.owners, s.stale = release(s.owners), release(s.stale)
}

// sessionEnded marks the views sess announced last as stale from now
func (s *Server) sessionEnded(sess *session) {
	now := s.now()

	s.viewsMu.Lock()
	defer s.viewsMu.Unlock()

	delete(s.sessions, sess)
	for view, owner := range s.owners {
		if owner == sess {
			delete(s.owners, view)
			if s.stale == nil {
				s.stale = make(map[Peer]time.Time)
			}
			s.stale[view] = now
		}
	}
	s.owners = release(s.owners)
}

func (s *Server) purgeStale() {
	now := s.now()
	grace := s.grace()

	s.viewsMu.Lock()
	defer s.viewsMu.Unlock()

	for view, since := range s.stale {
		for sess := range s.sessions {
			start := since
			if sess.opened.After(start) {
				start = sess.opened
			}
			if sess.speaker != view.Speaker || now.Before(start.Add(grace)) {
				continue
			}
			s.table.removePeer(view)
			delete(s.stale, view)
			log.Info("bmp view aged out", "speaker", view.Speaker, "peer", view.Address, "post_policy", view.PostPolicy)
			break
		}
	}
	s.stale = release(s.stale)
}

// sweep runs purgeStale until the server closes
func (s *Server) sweep() {
	defer s.wg.Done()

	tick := time.NewTicker(staleSweep)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.purgeStale()
		}
	}
}

func newServer(ln net.Listener) *Server {
	return &Server{
		listener:    ln,
		table:       newTable(),
		done:        make(chan struct{}),
		failed:      make(chan struct{}),
		conns:       make(map[net.Conn]struct{}),
		maxSessions: maxSessions,
	}
}

// Stats counts what the BMP listener saw since it started
type Stats struct {
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
	// contradicting itself, a bug in rfm, see table.fault
	Inconsistencies uint64
}

// Stats returns the counters of the BMP listener
func (s *Server) Stats() Stats {
	return Stats{
		SessionsRejected: s.sessionsRejected.Load(),
		ParseErrors:      s.parseErrors.Load(),
		RoutesRejected:   s.table.rejected.Load(),
		Inconsistencies:  s.table.faults.Load(),
	}
}

// Listen starts the BMP listener cfg configures, it returns nil, nil when
// cfg configures none
func Listen(cfg config.RIBConfig) (*Server, error) {
	if !cfg.BMP.Enabled() {
		return nil, nil
	}

	addr := cfg.BMP.Addr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen BMP %q: %w", addr, err)
	}

	s := newServer(ln)
	s.wg.Add(2)
	go s.accept()
	go s.sweep()

	return s, nil
}

func (s *Server) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	return s.table.enrich(src, dst)
}

// Lookup returns the best matching route for addr
func (s *Server) Lookup(addr netip.Addr) (Route, bool) {
	return s.table.lookup(addr)
}

// Summary counts what the RIB holds
func (s *Server) Summary() Summary {
	return s.table.summary()
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
func (s *Server) handleConn(conn net.Conn) {
	log.Info("bmp session opened", "remote", conn.RemoteAddr())
	sess := s.sessionOpened(conn)
	defer s.sessionEnded(sess)

	// the scanner starts small and doubles its buffer up to the largest
	// message the session sends, an idle session holds 4 KiB
	scanner := bufio.NewScanner(conn)
	scanner.Split(splitBMP)
	scanner.Buffer(nil, bmpScannerMaxBuf)

	var messages, parseErrors int
	var appliedLogged bool

	// addPath holds the decode options of at most maxViews peers whose peer
	// up shows ADD-PATH, nil for one whose peer up did not parse
	addPath := make(map[Peer][]*bgp.MarshallingOption)
	var overflow bool
	options := func(h bmp.BMPPeerHeader) []*bgp.MarshallingOption {
		peer := peerFromHeader(sess.speaker, h)
		peer.PostPolicy = false
		return addPath[peer]
	}
	// undecodable reports whether path ids the session cannot tell from
	// prefixes may lead the updates of the peer of h
	undecodable := func(h bmp.BMPPeerHeader) bool {
		peer := peerFromHeader(sess.speaker, h)
		peer.PostPolicy = false
		opts, held := addPath[peer]
		return held && opts == nil || !held && overflow
	}

	for scanner.Scan() {
		messages++
		if adjRIBOut(scanner.Bytes()) {
			continue
		}

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

		switch msg.Header.Type {
		case bmp.BMP_MSG_PEER_UP_NOTIFICATION:
			peer := peerFromHeader(sess.speaker, msg.PeerHeader)
			s.peerChanged(peer)
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
			peer := peerFromHeader(sess.speaker, msg.PeerHeader)
			s.peerChanged(peer)
			peer.PostPolicy = false
			delete(addPath, peer)
			log.Info("bmp peer down", "remote", conn.RemoteAddr(), "peer", peer.Address)
			continue
		}

		update, ok := updateFromBMP(sess.speaker, msg)
		if !ok {
			continue
		}
		if treatAsWithdraw {
			for _, route := range update.Reach {
				update.Withdraw = append(update.Withdraw, withdrawal{Prefix: route.Prefix, PathID: route.PathID})
			}
			update.Reach = nil
		}
		if !appliedLogged && (len(update.Reach) > 0 || len(update.Withdraw) > 0) {
			log.Info("bmp route monitoring applied", "remote", conn.RemoteAddr(), "reach", len(update.Reach), "withdraw", len(update.Withdraw))
			appliedLogged = true
		}
		s.apply(sess, update)
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

	log.Info("bmp session closed", "remote", conn.RemoteAddr(), "messages", messages, "parse_errors", parseErrors)
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

// adjRIBOut reports whether data is route monitoring of an Adj-RIB-Out (RFC
// 8671), the routes a router sends a peer rather than those it receives
func adjRIBOut(data []byte) bool {
	return len(data) > bmp.BMP_HEADER_SIZE+1 && data[5] == bmp.BMP_MSG_ROUTE_MONITORING && data[bmp.BMP_HEADER_SIZE+1]&bmp.BMP_PEER_FLAG_ADJ_RIB_TYP != 0
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
		rejected := s.sessionsRejected.Add(1)
		_ = conn.Close()
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

func peerFromHeader(speaker netip.Addr, h bmp.BMPPeerHeader) Peer {
	peer := Peer{Speaker: speaker, Distinguisher: h.PeerDistinguisher, PostPolicy: h.IsPostPolicy()}
	if addr, ok := netip.AddrFromSlice(h.PeerAddress); ok {
		peer.Address = addr.Unmap()
	}
	return peer
}

func updateFromBMP(speaker netip.Addr, msg *bmp.BMPMessage) (update, bool) {
	if msg.Header.Type != bmp.BMP_MSG_ROUTE_MONITORING {
		return update{}, false
	}

	body, ok := msg.Body.(*bmp.BMPRouteMonitoring)
	if !ok || body.BGPUpdate == nil {
		return update{}, false
	}

	updateMsg, ok := body.BGPUpdate.Body.(*bgp.BGPUpdate)
	if !ok {
		return update{}, false
	}

	attrs := routeAttrs(updateMsg.PathAttributes, msg.PeerHeader.Flags&bmp.BMP_PEER_FLAG_TWO_AS != 0)

	out := update{Peer: peerFromHeader(speaker, msg.PeerHeader)}
	reach := func(nlri bgp.AddrPrefixInterface) {
		if prefix, ok := prefixFromNLRI(nlri); ok {
			route := attrs.route(prefix, out.Peer, msg.PeerHeader.PeerAS)
			route.PathID = nlri.PathIdentifier()
			out.Reach = append(out.Reach, route)
		}
	}
	withdraw := func(nlri bgp.AddrPrefixInterface) {
		if prefix, ok := prefixFromNLRI(nlri); ok {
			out.Withdraw = append(out.Withdraw, withdrawal{Prefix: prefix, PathID: nlri.PathIdentifier()})
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

// insertRoute stores route in the view of its peer and updates best
// it must be called with mu held
func (t *table) insertRoute(route Route) {
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
func (t *table) admit(newView bool) bool {
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
func (t *table) deleteRoute(prefix netip.Prefix, pathID uint32, v *view) {
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
func (t *table) offered(prefix netip.Prefix, v *view, value viewRoute, added bool) {
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
func (t *table) withdrawn(prefix netip.Prefix, v *view) {
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
func (t *table) fault(what string, prefix netip.Prefix) {
	if t.faults.Add(1) == 1 {
		log.Error("rib table inconsistent, a bug in rfm", "fault", what, "prefix", prefix)
	}
}

// addView adds v to the views and keeps order sorted by preference
// it must be called with mu held
func (t *table) addView(v *view) {
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
func (t *table) dropView(v *view) {
	delete(t.views, v.peer)
	if i := slices.Index(t.order, v); i >= 0 {
		t.order = slices.Delete(t.order, i, i+1)
	}
}

// betterPeer orders the views totally, post policy first, which keeps the
// view that wins a prefix the same across updates
func betterPeer(a, b Peer) bool {
	if a.PostPolicy != b.PostPolicy {
		return a.PostPolicy
	}
	if c := a.Address.Compare(b.Address); c != 0 {
		return c < 0
	}
	if a.Distinguisher != b.Distinguisher {
		return a.Distinguisher < b.Distinguisher
	}
	return a.Speaker.Less(b.Speaker)
}

func (t *table) route(prefix netip.Prefix, v *view, value viewRoute) (Route, bool) {
	route := Route{
		Prefix:            prefix,
		OriginASN:         value.originASN,
		OriginASSet:       value.originASSet,
		Speaker:           v.peer.Speaker,
		PeerAddress:       v.peer.Address,
		PeerDistinguisher: v.peer.Distinguisher,
		PostPolicy:        v.peer.PostPolicy,
		PathID:            value.pathID,
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
	route.Truncated = routeMeta.Truncated
	return route, true
}

func (t *table) internMeta(meta routeMeta) uint64 {
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

func (t *table) releaseMeta(id uint64) {
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

// route shares the attribute slices with the other routes of the update
func (a attrs) route(prefix netip.Prefix, peer Peer, peerASN uint32) Route {
	return Route{
		Prefix:            prefix,
		OriginASN:         a.originASN,
		OriginASSet:       a.originASSet,
		ASPath:            a.asPath,
		Communities:       a.communities,
		LargeCommunities:  a.largeCommunities,
		Speaker:           peer.Speaker,
		PeerASN:           peerASN,
		PeerAddress:       peer.Address,
		PeerDistinguisher: peer.Distinguisher,
		PostPolicy:        peer.PostPolicy,
	}
}

// meta returns the leading maxPathLen ASNs and maxCommunities communities of each kind of r without a copy, and whether that cut any
func (r Route) meta() routeMeta {
	return routeMeta{
		ASPath:           r.ASPath[:min(len(r.ASPath), maxPathLen)],
		Communities:      r.Communities[:min(len(r.Communities), maxCommunities)],
		LargeCommunities: r.LargeCommunities[:min(len(r.LargeCommunities), maxCommunities)],
		PeerASN:          r.PeerASN,
		Truncated:        len(r.ASPath) > maxPathLen || len(r.Communities) > maxCommunities || len(r.LargeCommunities) > maxCommunities,
	}
}

func (m routeMeta) empty() bool {
	return len(m.ASPath) == 0 &&
		len(m.Communities) == 0 &&
		len(m.LargeCommunities) == 0 &&
		m.PeerASN == 0
}

func (m routeMeta) clone() routeMeta {
	m.ASPath = append([]uint32(nil), m.ASPath...)
	m.Communities = append([]uint32(nil), m.Communities...)
	m.LargeCommunities = append([]LargeCommunity(nil), m.LargeCommunities...)
	return m
}

func (m routeMeta) key() routeMetaKey {
	return routeMetaKey{
		ASPath:           encodeUint32s(m.ASPath),
		Communities:      encodeUint32s(m.Communities),
		LargeCommunities: encodeLargeCommunities(m.LargeCommunities),
		PeerASN:          m.PeerASN,
		Truncated:        m.Truncated,
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

// encodeUint32s writes values 4 bytes each into one string
func encodeUint32s(values []uint32) string {
	if len(values) == 0 {
		return ""
	}

	var b strings.Builder
	b.Grow(4 * len(values))
	for _, value := range values {
		writeUint32(&b, value)
	}
	return b.String()
}

func encodeLargeCommunities(values []LargeCommunity) string {
	if len(values) == 0 {
		return ""
	}

	var b strings.Builder
	b.Grow(12 * len(values))
	for _, value := range values {
		writeUint32(&b, value.GlobalAdmin)
		writeUint32(&b, value.LocalData1)
		writeUint32(&b, value.LocalData2)
	}
	return b.String()
}

func writeUint32(b *strings.Builder, value uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	b.Write(buf[:])
}
