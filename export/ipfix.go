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

const ipfixObservationDomainID uint32 = 1

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
	samplingProb           float64
	seqNumber              uint32
	ipv4TemplateID         uint16
	ipv6TemplateID         uint16
	ipv4TemplateSentAt     time.Time
	ipv6TemplateSentAt     time.Time
	templateRefreshTimeout time.Duration
	nowFunc                func() time.Time
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
		samplingProb:           1 / float64(sampleRate),
		ipv4TemplateID:         256,
		ipv6TemplateID:         257,
		templateRefreshTimeout: time.Duration(entities.TemplateRefreshTimeOut) * time.Second,
		nowFunc:                time.Now,
	}, nil
}

// Close closes the connection to the collector
func (e *IPFIXExporter) Close() error {
	if e == nil || e.conn == nil {
		return nil
	}
	return e.conn.Close()
}

// ExportFlow sends a completed flow as an IPFIX data record
func (e *IPFIXExporter) ExportFlow(flow collector.ExportedFlow) error {
	if e == nil || e.conn == nil {
		return fmt.Errorf("ipfix exporter is not initialized")
	}
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

	elements, err := e.dataElements(flow, isIPv6)
	if err != nil {
		return err
	}

	set, err := entities.MakeDataSet(templateID, elements)
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

	elements, err := templateInfoElements(isIPv6)
	if err != nil {
		return 0, nil, err
	}
	set, err := entities.MakeTemplateSet(templateID, elements)
	if err != nil {
		return 0, nil, err
	}
	return templateID, set, nil
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
	msg.SetObsDomainID(ipfixObservationDomainID)
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

func (e *IPFIXExporter) dataElements(flow collector.ExportedFlow, isIPv6 bool) ([]entities.InfoElementWithValue, error) {
	fields := ipfixFieldNames(isIPv6)

	srcAddr := flow.Key.SrcAddr.Unmap()
	dstAddr := flow.Key.DstAddr.Unmap()

	var ingressIf uint32
	var egressIf uint32
	if flow.Key.Dir == 0 {
		ingressIf = flow.Key.Ifindex
	} else {
		egressIf = flow.Key.Ifindex
	}

	elements := make([]entities.InfoElementWithValue, 0, len(fields))
	for _, name := range fields {
		ie, err := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		if err != nil {
			return nil, err
		}
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
	return elements, nil
}

func templateInfoElements(isIPv6 bool) ([]*entities.InfoElement, error) {
	fields := ipfixFieldNames(isIPv6)
	elements := make([]*entities.InfoElement, 0, len(fields))
	for _, name := range fields {
		ie, err := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		if err != nil {
			return nil, err
		}
		elements = append(elements, ie)
	}
	return elements, nil
}

func ipfixFieldNames(isIPv6 bool) []string {
	fields := make([]string, 0, len(ipfixCommonFields)+len(ipfixIPv4Fields))
	if isIPv6 {
		fields = append(fields, ipfixIPv6Fields...)
	} else {
		fields = append(fields, ipfixIPv4Fields...)
	}
	fields = append(fields, ipfixCommonFields...)
	return fields
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
