package export

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"golang.org/x/sys/unix"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
)

var loadIPFIXRegistry sync.Once

var (
	ipfixCommonFields = []string{
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"ingressInterface",
		"egressInterface",
		"flowDirection",
		"flowStartMilliseconds",
		"flowEndMilliseconds",
		"packetDeltaCount",
		"octetDeltaCount",
		"flowEndReason",
		"samplingProbability",
	}
	ipfixIPv4Fields = []string{
		"sourceIPv4Address",
		"destinationIPv4Address",
	}
	ipfixIPv6Fields = []string{
		"sourceIPv6Address",
		"destinationIPv6Address",
	}
)

const (
	ipfixIPv4TemplateID uint16 = 256
	ipfixIPv6TemplateID uint16 = 257

	// ipfixSetHeaderLen is the set id plus set length
	ipfixSetHeaderLen = 4
	// ipfixTemplateHeaderLen is the template id plus field count
	ipfixTemplateHeaderLen = 4
	// ipfixFieldSpecLen is one iana field specifier, id plus length
	ipfixFieldSpecLen = 4

	// ipfixGatherLimit caps how many queued records one gather collects
	// before the sender packs them, so a burst is split into messages
	// without waiting for the flush interval
	ipfixGatherLimit = 512

	ipfixDialBackoffMin = time.Second
	ipfixDialBackoffMax = 30 * time.Second
)

// IPFIXStats counts what the exporter did since it was created
type IPFIXStats struct {
	// Connected reports whether a socket to the collector is open
	Connected bool
	// Dials and DialErrors count socket setup attempts and failures
	Dials      uint64
	DialErrors uint64
	// Messages and Records count what went out on the wire
	Messages uint64
	Records  uint64
	// QueueDropped counts records refused because the queue was full
	QueueDropped uint64
	// Unsent counts records dropped because no socket was available
	Unsent uint64
	// EncodeErrors counts records that could not be turned into a data record
	EncodeErrors uint64
	// SendErrors counts failed sends by errno name, "other" when not an errno
	SendErrors map[string]uint64
}

// Failures sums every way a record can be lost
func (s IPFIXStats) Failures() uint64 {
	n := s.QueueDropped + s.Unsent + s.EncodeErrors + s.DialErrors
	for _, v := range s.SendErrors {
		n += v
	}
	return n
}

// IPFIXExporter sends flow records to a single UDP IPFIX collector
// ExportFlow only queues a record, a sender goroutine packs queued records
// into messages up to the configured size, refreshes templates, and sends
// the socket is dialed lazily and re-dialed with backoff after a failure, so
// the agent starts and keeps counting while the collector or the local bind
// address is unavailable, and every loss is counted in Stats
type IPFIXExporter struct {
	queue     chan collector.ExportedFlow
	flushReq  chan chan struct{}
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	// mu guards the socket, the endpoints read by isOwnExportFlow, and stats
	mu            sync.Mutex
	conn          *net.UDPConn
	localAddr     netip.Addr
	localPort     uint16
	collectorAddr netip.Addr
	collectorPort uint16
	remote        *net.UDPAddr
	localBind     *net.UDPAddr
	nextDial      time.Time
	dialBackoff   time.Duration
	dial          func(local, remote *net.UDPAddr) (*net.UDPConn, error)
	stats         IPFIXStats

	// sender state, touched by the sender goroutine only
	observationDomainID    uint32
	samplingProb           float64
	seqNumber              uint32
	templateRefreshTimeout time.Duration
	flushInterval          time.Duration
	maxMessageSize         int
	nowFunc                func() time.Time
	buf                    bytes.Buffer
	ipv4                   ipfixTemplate
	ipv6                   ipfixTemplate
}

// ipfixTemplate caches one template with its field lengths and refresh state
type ipfixTemplate struct {
	id        uint16
	names     []string
	elements  []*entities.InfoElement
	recordLen int
	setLen    int
	sentAt    time.Time
}

// NewIPFIX creates an IPFIX exporter for a single configured collector
func NewIPFIX(cfg config.IPFIXConfig, sampleRate uint32) (*IPFIXExporter, error) {
	if sampleRate == 0 {
		return nil, fmt.Errorf("sample rate must be > 0")
	}

	cfg = cfg.WithDefaults()
	if !cfg.Enabled() {
		return nil, fmt.Errorf("ipfix exporter requires a collector host or port")
	}

	loadIPFIXRegistry.Do(registry.LoadRegistry)

	ipv4, err := newIPFIXTemplate(ipfixIPv4TemplateID, ipfixIPv4Fields, ipfixCommonFields)
	if err != nil {
		return nil, err
	}
	ipv6, err := newIPFIXTemplate(ipfixIPv6TemplateID, ipfixIPv6Fields, ipfixCommonFields)
	if err != nil {
		return nil, err
	}

	remote, err := net.ResolveUDPAddr("udp", cfg.Addr())
	if err != nil {
		return nil, err
	}
	collectorAddr, ok := netip.AddrFromSlice(remote.IP)
	if !ok {
		return nil, fmt.Errorf("collector address %q is not a valid ip address", remote.IP.String())
	}

	var localBind *net.UDPAddr
	if cfg.Bind.Enabled() {
		localBind, err = net.ResolveUDPAddr("udp", cfg.Bind.Addr())
		if err != nil {
			return nil, fmt.Errorf("resolve ipfix bind address %q: %w", cfg.Bind.Addr(), err)
		}
	}

	e := &IPFIXExporter{
		queue:         make(chan collector.ExportedFlow, cfg.QueueSize),
		flushReq:      make(chan chan struct{}),
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		collectorAddr: collectorAddr.Unmap(),
		collectorPort: uint16(remote.Port),
		remote:        remote,
		localBind:     localBind,
		dial: func(local, remote *net.UDPAddr) (*net.UDPConn, error) {
			return net.DialUDP("udp", local, remote)
		},
		observationDomainID:    cfg.ObservationDomainID,
		samplingProb:           1 / float64(sampleRate),
		templateRefreshTimeout: cfg.TemplateRefresh,
		flushInterval:          cfg.FlushInterval,
		maxMessageSize:         cfg.MaxMessageSize,
		nowFunc:                time.Now,
		ipv4:                   ipv4,
		ipv6:                   ipv6,
	}
	e.stats.SendErrors = make(map[string]uint64)

	// a failed first dial is not fatal, the sender retries with backoff so
	// a bind address that appears after boot still gets its exporter
	if err := e.ensureConn(time.Now()); err != nil {
		log.Warn("ipfix collector not reachable yet", "addr", cfg.Addr(), "err", err)
	}

	go e.run()
	return e, nil
}

func ipfixFieldNames(family, common []string) []string {
	names := make([]string, 0, len(family)+len(common))
	names = append(names, family...)
	names = append(names, common...)
	return names
}

func newIPFIXTemplate(id uint16, family, common []string) (ipfixTemplate, error) {
	names := ipfixFieldNames(family, common)

	t := ipfixTemplate{
		id:       id,
		names:    names,
		elements: make([]*entities.InfoElement, len(names)),
	}
	for i, name := range names {
		ie, err := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		if err != nil {
			return ipfixTemplate{}, fmt.Errorf("ipfix info element %q: %w", name, err)
		}
		t.elements[i] = ie
		t.recordLen += int(ie.Len)
	}
	t.setLen = ipfixSetHeaderLen + ipfixTemplateHeaderLen + len(names)*ipfixFieldSpecLen
	return t, nil
}

// Stats returns a snapshot of the exporter counters
func (e *IPFIXExporter) Stats() IPFIXStats {
	e.mu.Lock()
	defer e.mu.Unlock()

	s := e.stats
	s.Connected = e.conn != nil
	s.SendErrors = make(map[string]uint64, len(e.stats.SendErrors))
	maps.Copy(s.SendErrors, e.stats.SendErrors)
	return s
}

// Close sends what is still queued and closes the socket
func (e *IPFIXExporter) Close() error {
	e.closeOnce.Do(func() {
		close(e.stop)
	})
	<-e.done

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn == nil {
		return nil
	}
	err := e.conn.Close()
	e.conn = nil
	return err
}

// Flush sends every queued record now and returns once they went out
func (e *IPFIXExporter) Flush() error {
	req := make(chan struct{})
	select {
	case e.flushReq <- req:
		<-req
		return nil
	case <-e.done:
		return errors.New("ipfix exporter closed")
	}
}

// ExportFlow queues a completed flow for export
// it returns an error when the queue is full, the record is then lost
func (e *IPFIXExporter) ExportFlow(flow collector.ExportedFlow) error {
	if e.isOwnExportFlow(flow) {
		return nil
	}

	select {
	case e.queue <- flow:
		return nil
	default:
		e.mu.Lock()
		e.stats.QueueDropped++
		e.mu.Unlock()
		return errors.New("ipfix queue full")
	}
}

// run is the sender goroutine
// records gather for up to flushInterval after the first one arrives, or
// until ipfixGatherLimit records are waiting, then go out as messages
func (e *IPFIXExporter) run() {
	defer close(e.done)

	var (
		pending []collector.ExportedFlow
		timer   *time.Timer
		timerC  <-chan time.Time
	)
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
			timer = nil
			timerC = nil
		}
	}

	for {
		select {
		case flow := <-e.queue:
			pending = append(pending, flow)
			if timer == nil {
				timer = time.NewTimer(e.flushInterval)
				timerC = timer.C
			}
			if len(pending) >= ipfixGatherLimit {
				stopTimer()
				e.sendAll(pending)
				pending = pending[:0]
			}
		case <-timerC:
			timer = nil
			timerC = nil
			e.sendAll(pending)
			pending = pending[:0]
		case req := <-e.flushReq:
			stopTimer()
			pending = e.drain(pending)
			e.sendAll(pending)
			pending = pending[:0]
			close(req)
		case <-e.stop:
			stopTimer()
			pending = e.drain(pending)
			e.sendAll(pending)
			return
		}
	}
}

// drain moves every record already queued into pending without blocking
func (e *IPFIXExporter) drain(pending []collector.ExportedFlow) []collector.ExportedFlow {
	for {
		select {
		case flow := <-e.queue:
			pending = append(pending, flow)
		default:
			return pending
		}
	}
}

// ipfixMessage accumulates records for one datagram
type ipfixMessage struct {
	ipv4     []collector.ExportedFlow
	ipv6     []collector.ExportedFlow
	withIPv4 bool
	withIPv6 bool
}

// sendAll packs pending records into messages no larger than maxMessageSize
// and sends them, one message can carry an ipv4 and an ipv6 data set
func (e *IPFIXExporter) sendAll(pending []collector.ExportedFlow) {
	if len(pending) == 0 {
		return
	}

	now := e.nowFunc()
	if err := e.ensureConn(now); err != nil {
		e.mu.Lock()
		e.stats.Unsent += uint64(len(pending))
		e.mu.Unlock()
		return
	}

	// templates that are due go into the first message that carries their
	// family, so their space is reserved in the budget until they are sent
	ipv4Due := e.templateDue(&e.ipv4, now)
	ipv6Due := e.templateDue(&e.ipv6, now)

	var msg ipfixMessage
	for _, flow := range pending {
		isIPv6, err := flowIsIPv6(flow)
		if err != nil {
			e.mu.Lock()
			e.stats.EncodeErrors++
			e.mu.Unlock()
			continue
		}

		if e.messageLen(msg, isIPv6, ipv4Due, ipv6Due) > e.maxMessageSize && e.messageRecords(msg) > 0 {
			sent4, sent6 := e.send(msg, now, ipv4Due, ipv6Due)
			ipv4Due = ipv4Due && !sent4
			ipv6Due = ipv6Due && !sent6
			msg = ipfixMessage{}
		}
		if isIPv6 {
			msg.ipv6 = append(msg.ipv6, flow)
			msg.withIPv6 = true
		} else {
			msg.ipv4 = append(msg.ipv4, flow)
			msg.withIPv4 = true
		}
	}
	if e.messageRecords(msg) > 0 {
		e.send(msg, now, ipv4Due, ipv6Due)
	}
}

func (e *IPFIXExporter) messageRecords(msg ipfixMessage) int {
	return len(msg.ipv4) + len(msg.ipv6)
}

// messageLen is the wire size of msg with one more record of the given
// family added, templates counted when they are due
func (e *IPFIXExporter) messageLen(msg ipfixMessage, addIPv6, ipv4Due, ipv6Due bool) int {
	n4, n6 := len(msg.ipv4), len(msg.ipv6)
	if addIPv6 {
		n6++
	} else {
		n4++
	}
	size := entities.MsgHeaderLength
	if n4 > 0 {
		size += ipfixSetHeaderLen + n4*e.ipv4.recordLen
		if ipv4Due {
			size += e.ipv4.setLen
		}
	}
	if n6 > 0 {
		size += ipfixSetHeaderLen + n6*e.ipv6.recordLen
		if ipv6Due {
			size += e.ipv6.setLen
		}
	}
	return size
}

func (e *IPFIXExporter) templateDue(t *ipfixTemplate, now time.Time) bool {
	return t.sentAt.IsZero() || now.Sub(t.sentAt) >= e.templateRefreshTimeout
}

// send encodes and sends one message, it reports which templates went out
func (e *IPFIXExporter) send(msg ipfixMessage, now time.Time, ipv4Due, ipv6Due bool) (sent4, sent6 bool) {
	var sets []entities.Set
	var dataRecords uint32

	if len(msg.ipv4) > 0 && ipv4Due {
		set, err := entities.MakeTemplateSet(e.ipv4.id, e.ipv4.elements)
		if err != nil {
			e.countEncodeError(uint64(e.messageRecords(msg)))
			return false, false
		}
		sets = append(sets, set)
		sent4 = true
	}
	if len(msg.ipv6) > 0 && ipv6Due {
		set, err := entities.MakeTemplateSet(e.ipv6.id, e.ipv6.elements)
		if err != nil {
			e.countEncodeError(uint64(e.messageRecords(msg)))
			return false, false
		}
		sets = append(sets, set)
		sent6 = true
	}
	for _, family := range []struct {
		flows []collector.ExportedFlow
		tmpl  *ipfixTemplate
		isV6  bool
	}{{msg.ipv4, &e.ipv4, false}, {msg.ipv6, &e.ipv6, true}} {
		if len(family.flows) == 0 {
			continue
		}
		set := entities.NewSet(false)
		if err := set.PrepareSet(entities.Data, family.tmpl.id); err != nil {
			e.countEncodeError(uint64(len(family.flows)))
			continue
		}
		for _, flow := range family.flows {
			if err := set.AddRecord(e.dataElements(flow, family.isV6), family.tmpl.id); err != nil {
				e.countEncodeError(1)
				continue
			}
			dataRecords++
		}
		if set.GetNumberOfRecords() > 0 {
			sets = append(sets, set)
		}
	}
	if dataRecords == 0 {
		return false, false
	}

	if err := e.write(now, sets, dataRecords); err != nil {
		e.countSendError(err, uint64(dataRecords), now)
		return false, false
	}

	if sent4 {
		e.ipv4.sentAt = now
	}
	if sent6 {
		e.ipv6.sentAt = now
	}
	e.mu.Lock()
	e.stats.Messages++
	e.stats.Records += uint64(dataRecords)
	e.mu.Unlock()
	return sent4, sent6
}

func (e *IPFIXExporter) write(now time.Time, sets []entities.Set, dataRecords uint32) error {
	msgLen := entities.MsgHeaderLength
	for _, set := range sets {
		set.UpdateLenInHeader()
		msgLen += set.GetSetLength()
	}
	if msgLen > entities.MaxSocketMsgSize {
		return fmt.Errorf("message size %d exceeds max socket buffer size", msgLen)
	}

	msg := entities.NewMessage(false)
	msg.SetVersion(10)
	msg.SetObsDomainID(e.observationDomainID)
	msg.SetMessageLen(uint16(msgLen))
	msg.SetExportTime(uint32(now.Unix()))
	msg.SetSequenceNum(e.seqNumber)

	e.buf.Reset()
	e.buf.Grow(msgLen)
	e.buf.Write(msg.GetMsgHeader())
	for _, set := range sets {
		e.buf.Write(set.GetHeaderBuffer())
		b := e.buf.AvailableBuffer()
		for _, record := range set.GetRecords() {
			var err error
			b, err = record.AppendToBuffer(b)
			if err != nil {
				return err
			}
		}
		e.buf.Write(b)
	}

	e.mu.Lock()
	conn := e.conn
	e.mu.Unlock()
	if conn == nil {
		return errors.New("ipfix socket not connected")
	}

	written, err := conn.Write(e.buf.Bytes())
	if err != nil {
		return err
	}
	if written != msgLen {
		return fmt.Errorf("short udp write: wrote %d bytes, want %d", written, msgLen)
	}
	e.seqNumber += dataRecords
	return nil
}

func (e *IPFIXExporter) countEncodeError(records uint64) {
	e.mu.Lock()
	e.stats.EncodeErrors += records
	e.mu.Unlock()
}

// countSendError classifies err by errno and schedules a re-dial when the
// socket itself is unusable
func (e *IPFIXExporter) countSendError(err error, records uint64, now time.Time) {
	name := errnoName(err)

	e.mu.Lock()
	e.stats.SendErrors[name]++
	total := e.stats.SendErrors[name]
	if socketUnusable(err) && e.conn != nil {
		_ = e.conn.Close()
		e.conn = nil
		e.scheduleDialLocked(now)
	}
	e.mu.Unlock()

	// the first failure of each kind is worth a log line, later ones are
	// visible as counters
	if total == 1 {
		log.Error("ipfix send", "errno", name, "records", records, "err", err)
	}
}

// errnoName returns the symbolic errno behind err, or "other"
func errnoName(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if name := unix.ErrnoName(errno); name != "" {
			return name
		}
		return errno.Error()
	}
	return "other"
}

// socketUnusable reports whether a send error means the socket must be
// re-dialed rather than retried, an icmp error such as ECONNREFUSED or a
// firewall verdict such as EPERM keeps the socket
func socketUnusable(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case unix.ENETUNREACH, unix.EHOSTUNREACH, unix.ENETDOWN, unix.EADDRNOTAVAIL,
		unix.EPIPE, unix.ENOTCONN, unix.EBADF, unix.EINVAL:
		return true
	}
	return false
}

// ensureConn dials the collector when no socket is open and the backoff
// allows another attempt
// the dial runs without the lock so a slow dial never stalls ExportFlow
func (e *IPFIXExporter) ensureConn(now time.Time) error {
	e.mu.Lock()
	if e.conn != nil {
		e.mu.Unlock()
		return nil
	}
	if now.Before(e.nextDial) {
		e.mu.Unlock()
		return errors.New("ipfix socket not connected, retry pending")
	}
	e.stats.Dials++
	dial, localBind, remote := e.dial, e.localBind, e.remote
	e.mu.Unlock()

	conn, err := dial(localBind, remote)
	if err != nil {
		e.dialFailed(now)
		return fmt.Errorf("dial ipfix collector %q: %w", remote.String(), err)
	}

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		e.dialFailed(now)
		return fmt.Errorf("unexpected local address type %T", conn.LocalAddr())
	}
	localAddr, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		_ = conn.Close()
		e.dialFailed(now)
		return fmt.Errorf("local address %q is not a valid ip address", local.IP.String())
	}

	e.mu.Lock()
	e.conn = conn
	e.localAddr = localAddr.Unmap()
	e.localPort = uint16(local.Port)
	e.dialBackoff = 0
	e.nextDial = time.Time{}
	e.mu.Unlock()
	return nil
}

func (e *IPFIXExporter) dialFailed(now time.Time) {
	e.mu.Lock()
	e.stats.DialErrors++
	e.scheduleDialLocked(now)
	e.mu.Unlock()
}

// scheduleDialLocked doubles the backoff up to the cap
// it must be called with mu held
func (e *IPFIXExporter) scheduleDialLocked(now time.Time) {
	if e.dialBackoff == 0 {
		e.dialBackoff = ipfixDialBackoffMin
	} else {
		e.dialBackoff = min(e.dialBackoff*2, ipfixDialBackoffMax)
	}
	e.nextDial = now.Add(e.dialBackoff)
}

func (e *IPFIXExporter) dataElements(flow collector.ExportedFlow, isIPv6 bool) []entities.InfoElementWithValue {
	t := &e.ipv4
	if isIPv6 {
		t = &e.ipv6
	}

	srcAddr := flow.Key.SrcAddr.Unmap()
	dstAddr := flow.Key.DstAddr.Unmap()

	var ingressIf uint32
	var egressIf uint32
	if flow.Key.Dir == 0 {
		ingressIf = flow.Key.Ifindex
	} else {
		egressIf = flow.Key.Ifindex
	}

	elements := make([]entities.InfoElementWithValue, 0, len(t.names))
	for i, name := range t.names {
		ie := t.elements[i]
		switch name {
		case "sourceIPv4Address", "sourceIPv6Address":
			elements = append(elements, entities.NewIPAddressInfoElement(ie, net.IP(srcAddr.AsSlice())))
		case "destinationIPv4Address", "destinationIPv6Address":
			elements = append(elements, entities.NewIPAddressInfoElement(ie, net.IP(dstAddr.AsSlice())))
		case "sourceTransportPort":
			elements = append(elements, entities.NewUnsigned16InfoElement(ie, flow.Key.SrcPort))
		case "destinationTransportPort":
			elements = append(elements, entities.NewUnsigned16InfoElement(ie, flow.Key.DstPort))
		case "protocolIdentifier":
			elements = append(elements, entities.NewUnsigned8InfoElement(ie, flow.Key.Proto))
		case "ingressInterface":
			elements = append(elements, entities.NewUnsigned32InfoElement(ie, ingressIf))
		case "egressInterface":
			elements = append(elements, entities.NewUnsigned32InfoElement(ie, egressIf))
		case "flowDirection":
			elements = append(elements, entities.NewUnsigned8InfoElement(ie, flow.Key.Dir))
		case "flowStartMilliseconds":
			elements = append(elements, entities.NewDateTimeMillisecondsInfoElement(ie, uint64(flow.Entry.FirstSeen.UnixMilli())))
		case "flowEndMilliseconds":
			elements = append(elements, entities.NewDateTimeMillisecondsInfoElement(ie, uint64(flow.Entry.LastSeen.UnixMilli())))
		case "packetDeltaCount":
			elements = append(elements, entities.NewUnsigned64InfoElement(ie, flow.Entry.Packets))
		case "octetDeltaCount":
			elements = append(elements, entities.NewUnsigned64InfoElement(ie, flow.Entry.Bytes))
		case "flowEndReason":
			elements = append(elements, entities.NewUnsigned8InfoElement(ie, flow.EndReason))
		case "samplingProbability":
			// records carry the share of wire packets they stand for, which
			// tracks runtime rate changes, an empty estimate falls back to
			// the configured rate
			prob := e.samplingProb
			if flow.Entry.EstPackets > 0 {
				prob = flow.Entry.SamplingProbability()
			}
			elements = append(elements, entities.NewFloat64InfoElement(ie, prob))
		}
	}
	return elements
}

func flowIsIPv6(flow collector.ExportedFlow) (bool, error) {
	src := flow.Key.SrcAddr.Unmap()
	dst := flow.Key.DstAddr.Unmap()
	if !src.IsValid() || !dst.IsValid() {
		return false, fmt.Errorf("flow has invalid addresses")
	}
	if src.Is4() != dst.Is4() {
		return false, fmt.Errorf("flow address families do not match")
	}
	return src.Is6(), nil
}

// isOwnExportFlow reports whether flow is this exporter's own udp stream to
// the collector, which must not be exported again
func (e *IPFIXExporter) isOwnExportFlow(flow collector.ExportedFlow) bool {
	if flow.Key.Proto != 17 {
		return false
	}

	e.mu.Lock()
	connected := e.conn != nil
	localAddr, localPort := e.localAddr, e.localPort
	e.mu.Unlock()
	if !connected {
		return false
	}

	if flow.Key.SrcPort != localPort || flow.Key.DstPort != e.collectorPort {
		return false
	}
	src := flow.Key.SrcAddr.Unmap()
	dst := flow.Key.DstAddr.Unmap()
	if !src.IsValid() || !dst.IsValid() {
		return false
	}
	return src == localAddr && dst == e.collectorAddr
}
