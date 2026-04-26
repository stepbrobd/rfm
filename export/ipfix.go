package export

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
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

// IPFIXExporter sends completed flows to a single UDP IPFIX collector
type IPFIXExporter struct {
	mu                     sync.Mutex
	conn                   *net.UDPConn
	buf                    bytes.Buffer
	localAddr              netip.Addr
	localPort              uint16
	collectorAddr          netip.Addr
	collectorPort          uint16
	observationDomainID    uint32
	samplingProb           float64
	seqNumber              uint32
	ipv4TemplateID         uint16
	ipv6TemplateID         uint16
	ipv4TemplateSentAt     time.Time
	ipv6TemplateSentAt     time.Time
	templateRefreshTimeout time.Duration
	nowFunc                func() time.Time
	ipv4Fields             ipfixFields
	ipv6Fields             ipfixFields
}

// ipfixFields caches the field name and registry InfoElement for one template
type ipfixFields struct {
	names    []string
	elements []*entities.InfoElement
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

	ipv4Fields, err := newIPFIXFields(ipfixIPv4Fields, ipfixCommonFields)
	if err != nil {
		return nil, err
	}
	ipv6Fields, err := newIPFIXFields(ipfixIPv6Fields, ipfixCommonFields)
	if err != nil {
		return nil, err
	}

	remote, err := net.ResolveUDPAddr("udp", cfg.Addr())
	if err != nil {
		return nil, err
	}

	var localBind *net.UDPAddr
	if cfg.Bind.Enabled() {
		localBind, err = net.ResolveUDPAddr("udp", cfg.Bind.Addr())
		if err != nil {
			return nil, fmt.Errorf("resolve ipfix bind address %q: %w", cfg.Bind.Addr(), err)
		}
	}

	conn, err := net.DialUDP("udp", localBind, remote)
	if err != nil {
		return nil, fmt.Errorf("dial ipfix collector %q: %w", cfg.Addr(), err)
	}

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("unexpected local address type %T", conn.LocalAddr())
	}

	localAddr, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("local address %q is not a valid ip address", local.IP.String())
	}
	collectorAddr, ok := netip.AddrFromSlice(remote.IP)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("collector address %q is not a valid ip address", remote.IP.String())
	}

	return &IPFIXExporter{
		conn:                   conn,
		localAddr:              localAddr.Unmap(),
		localPort:              uint16(local.Port),
		collectorAddr:          collectorAddr.Unmap(),
		collectorPort:          uint16(remote.Port),
		observationDomainID:    cfg.ObservationDomainID,
		samplingProb:           1 / float64(sampleRate),
		ipv4TemplateID:         256,
		ipv6TemplateID:         257,
		templateRefreshTimeout: cfg.TemplateRefresh,
		nowFunc:                time.Now,
		ipv4Fields:             ipv4Fields,
		ipv6Fields:             ipv6Fields,
	}, nil
}

func newIPFIXFields(family, common []string) (ipfixFields, error) {
	names := ipfixFieldNames(family, common)
	elements := make([]*entities.InfoElement, len(names))
	for i, name := range names {
		ie, err := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		if err != nil {
			return ipfixFields{}, fmt.Errorf("ipfix info element %q: %w", name, err)
		}
		elements[i] = ie
	}
	return ipfixFields{names: names, elements: elements}, nil
}

func ipfixFieldNames(family, common []string) []string {
	names := make([]string, 0, len(family)+len(common))
	names = append(names, family...)
	names = append(names, common...)
	return names
}

// Close closes the connection to the collector
func (e *IPFIXExporter) Close() error {
	return e.conn.Close()
}

// ExportFlow sends a completed flow as an IPFIX data record
func (e *IPFIXExporter) ExportFlow(flow collector.ExportedFlow) error {
	if e.isOwnExportFlow(flow) {
		return nil
	}

	isIPv6, err := flowIsIPv6(flow)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.nowFunc()
	templateID, templateSet, err := e.templateSetIfNeededLocked(isIPv6, now)
	if err != nil {
		return err
	}

	set, err := entities.MakeDataSet(templateID, e.dataElements(flow, isIPv6))
	if err != nil {
		return err
	}
	if templateSet != nil {
		if err := e.sendSetsLocked(now, templateSet, set); err != nil {
			return err
		}
		e.markTemplateSentLocked(isIPv6, now)
		return nil
	}
	return e.sendSetsLocked(now, set)
}

func (e *IPFIXExporter) templateSetIfNeededLocked(isIPv6 bool, now time.Time) (uint16, entities.Set, error) {
	templateID := e.ipv4TemplateID
	sentAt := e.ipv4TemplateSentAt
	if isIPv6 {
		templateID = e.ipv6TemplateID
		sentAt = e.ipv6TemplateSentAt
	}
	if !sentAt.IsZero() && now.Sub(sentAt) < e.templateRefreshTimeout {
		return templateID, nil, nil
	}

	set, err := entities.MakeTemplateSet(templateID, e.fields(isIPv6).elements)
	if err != nil {
		return 0, nil, err
	}
	return templateID, set, nil
}

func (e *IPFIXExporter) fields(isIPv6 bool) ipfixFields {
	if isIPv6 {
		return e.ipv6Fields
	}
	return e.ipv4Fields
}

func (e *IPFIXExporter) markTemplateSentLocked(isIPv6 bool, now time.Time) {
	if isIPv6 {
		e.ipv6TemplateSentAt = now
		return
	}
	e.ipv4TemplateSentAt = now
}

func (e *IPFIXExporter) sendSetsLocked(now time.Time, sets ...entities.Set) error {
	msgLen := entities.MsgHeaderLength
	var dataRecords uint32
	for _, set := range sets {
		set.UpdateLenInHeader()
		msgLen += set.GetSetLength()
		if set.GetSetType() == entities.Data {
			dataRecords += set.GetNumberOfRecords()
		}
	}
	if msgLen > entities.MaxSocketMsgSize {
		return fmt.Errorf("message size exceeds max socket buffer size")
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

	written, err := e.conn.Write(e.buf.Bytes())
	if err != nil {
		return err
	}
	if written != msgLen {
		return fmt.Errorf("short udp write: wrote %d bytes, want %d", written, msgLen)
	}
	e.seqNumber += dataRecords
	return nil
}

func (e *IPFIXExporter) dataElements(flow collector.ExportedFlow, isIPv6 bool) []entities.InfoElementWithValue {
	f := e.fields(isIPv6)

	srcAddr := flow.Key.SrcAddr.Unmap()
	dstAddr := flow.Key.DstAddr.Unmap()

	var ingressIf uint32
	var egressIf uint32
	if flow.Key.Dir == 0 {
		ingressIf = flow.Key.Ifindex
	} else {
		egressIf = flow.Key.Ifindex
	}

	elements := make([]entities.InfoElementWithValue, 0, len(f.names))
	for i, name := range f.names {
		ie := f.elements[i]
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
			elements = append(elements, entities.NewFloat64InfoElement(ie, e.samplingProb))
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

func (e *IPFIXExporter) isOwnExportFlow(flow collector.ExportedFlow) bool {
	if flow.Key.Proto != 17 {
		return false
	}
	if flow.Key.SrcPort != e.localPort || flow.Key.DstPort != e.collectorPort {
		return false
	}
	src := flow.Key.SrcAddr.Unmap()
	dst := flow.Key.DstAddr.Unmap()
	if !src.IsValid() || !dst.IsValid() {
		return false
	}
	return src == e.localAddr && dst == e.collectorAddr
}
