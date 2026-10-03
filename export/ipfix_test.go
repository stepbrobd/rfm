package export

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vmware/go-ipfix/pkg/registry"
	"golang.org/x/sys/unix"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
)

// testIPFIXConfig returns an IPFIXConfig with sane defaults filled in
// the agent gets these from config.Load, but tests construct the config directly
func testIPFIXConfig(host string, port int) config.IPFIXConfig {
	return config.IPFIXConfig{
		Host:                host,
		Port:                port,
		TemplateRefresh:     60 * time.Second,
		ObservationDomainID: 1,
	}
}

type decodedIPFIXMessage struct {
	Version             uint16
	Length              uint16
	SequenceNum         uint32
	ObservationDomainID uint32
	Sets                []decodedIPFIXSet
}

type decodedIPFIXSet struct {
	ID      uint16
	Payload []byte
}

type decodedTemplateField struct {
	ID     uint16
	Length uint16
	Pen    uint32
	HasPen bool
}

func TestIPFIXExportsEvictedFlowsOverUDP(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	for _, tc := range []struct {
		name         string
		src          netip.Addr
		dst          netip.Addr
		srcFieldName string
		dstFieldName string
		srcIP        net.IP
		dstIP        net.IP
		templateID   uint16
	}{
		{
			name:         "ipv4",
			src:          netip.MustParseAddr("::ffff:10.0.0.1"),
			dst:          netip.MustParseAddr("::ffff:10.0.0.2"),
			srcFieldName: "sourceIPv4Address",
			dstFieldName: "destinationIPv4Address",
			srcIP:        net.ParseIP("10.0.0.1").To4(),
			dstIP:        net.ParseIP("10.0.0.2").To4(),
			templateID:   256,
		},
		{
			name:         "ipv6",
			src:          netip.MustParseAddr("2001:db8::1"),
			dst:          netip.MustParseAddr("2001:db8::2"),
			srcFieldName: "sourceIPv6Address",
			dstFieldName: "destinationIPv6Address",
			srcIP:        net.ParseIP("2001:db8::1"),
			dstIP:        net.ParseIP("2001:db8::2"),
			templateID:   257,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := startIPFIXListener(t)
			addr := conn.LocalAddr().(*net.UDPAddr)

			exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 100)
			if err != nil {
				t.Fatalf("NewIPFIX: %v", err)
			}
			defer exp.Close()

			c := collector.New(10*time.Second, nil, config.DefaultMaxFlows)
			c.SetFlowExporter(exp)
			c.SetSampleRate(100, 0)

			t0 := time.Unix(1_700_000_000, 0).UTC()
			ev := collector.FlowEvent{
				Ifindex: 7,
				Dir:     0,
				Proto:   17,
				SrcAddr: tc.src,
				DstAddr: tc.dst,
				SrcPort: 12345,
				DstPort: 53,
				Segs:    1,
				Len:     512,
			}
			c.Record(ev, t0)
			c.Evict(t0.Add(11 * time.Second))
			if err := exp.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}

			msg := mustReadIPFIXDatagram(t, conn)
			if got := msg.ObservationDomainID; got != 1 {
				t.Fatalf("observation domain id = %d, want 1", got)
			}
			if got := len(msg.Sets); got != 2 {
				t.Fatalf("set count = %d, want 2", got)
			}
			if got := msg.Sets[0].ID; got != entitiesTemplateSetID {
				t.Fatalf("template set id = %d, want %d", got, entitiesTemplateSetID)
			}
			if got := msg.Sets[1].ID; got != tc.templateID {
				t.Fatalf("data set id = %d, want %d", got, tc.templateID)
			}

			templateID, fields := parseTemplateSet(t, msg.Sets[0])
			if templateID != tc.templateID {
				t.Fatalf("template id = %d, want %d", templateID, tc.templateID)
			}
			assertTemplateFields(t, fields, templateFieldNames(tc.templateID == 257))

			record := parseDataRecord(t, msg.Sets[1], fields)
			assertIPFIXDataIP(t, record, tc.srcFieldName, tc.srcIP)
			assertIPFIXDataIP(t, record, tc.dstFieldName, tc.dstIP)
			assertIPFIXDataUInt16(t, record, "sourceTransportPort", 12345)
			assertIPFIXDataUInt16(t, record, "destinationTransportPort", 53)
			assertIPFIXDataUInt8(t, record, "protocolIdentifier", 17)
			assertIPFIXDataUInt32(t, record, "ingressInterface", 7)
			assertIPFIXDataUInt32(t, record, "egressInterface", 0)
			assertIPFIXDataUInt8(t, record, "flowDirection", 0)
			assertIPFIXDataUInt64(t, record, "flowStartMilliseconds", uint64(t0.UnixMilli()))
			assertIPFIXDataUInt64(t, record, "flowEndMilliseconds", uint64(t0.UnixMilli()))
			assertIPFIXDataUInt64(t, record, "packetDeltaCount", 1)
			assertIPFIXDataUInt64(t, record, "octetDeltaCount", 512)
			assertIPFIXDataUInt8(t, record, "flowEndReason", collector.FlowEndReasonIdleTimeout)
			assertIPFIXDataFloat64Range(t, record, "samplingProbability", 0.0099, 0.0101)
		})
	}
}

func TestIPFIXOctetDeltaCountCarriesIPBytes(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	c := collector.New(10*time.Second, nil, config.DefaultMaxFlows)
	c.SetFlowExporter(exp)

	t0 := time.Unix(1_700_000_000, 0).UTC()
	// a gro skb of three 1500 byte ip packets, each behind an ethernet header
	gro := collector.FlowEvent{
		Ifindex: 7, Dir: 0, Proto: 6,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		SrcPort: 40000, DstPort: 443,
		Segs: 3, Len: 3 * 1514, L2Len: 14,
	}
	// one 86 byte ip packet behind ethernet and a vlan tag
	tagged := gro
	tagged.Segs, tagged.Len, tagged.L2Len = 1, 104, 18
	c.Record(gro, t0)
	c.Record(tagged, t0)

	// prometheus keeps counting wire bytes
	if got := c.Flows()[gro.Key()].Bytes; got != 3*1514+104 {
		t.Fatalf("flow bytes = %d, want the %d wire bytes", got, 3*1514+104)
	}

	c.Evict(t0.Add(11 * time.Second))
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	msg := mustReadIPFIXDatagram(t, conn)
	if got := len(msg.Sets); got != 2 {
		t.Fatalf("set count = %d, want template and data", got)
	}
	_, fields := parseTemplateSet(t, msg.Sets[0])
	record := parseDataRecord(t, msg.Sets[1], fields)
	assertIPFIXDataUInt64(t, record, "packetDeltaCount", 4)
	// octetDeltaCount is ip header plus payload (rfc 7012), no l2 header
	assertIPFIXDataUInt64(t, record, "octetDeltaCount", 3*1500+86)
}

func TestIPFIXUsesConfiguredObservationDomainID(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	cfg := testIPFIXConfig(addr.IP.String(), addr.Port)
	cfg.ObservationDomainID = 4242
	exp, err := NewIPFIX(cfg, 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	flow := exportedFlow(
		collector.FlowKey{
			Ifindex: 1, Dir: 0, Proto: 6,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			SrcPort: 1234, DstPort: 80,
		},
		collector.FlowEntry{
			FirstSeen: now, LastSeen: now, Packets: 1, IPBytes: 100,
		},
		collector.FlowEndReasonIdleTimeout,
	)

	if err := exp.ExportFlow(flow); err != nil {
		t.Fatalf("ExportFlow: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	msg := mustReadIPFIXDatagram(t, conn)
	if got := msg.ObservationDomainID; got != 4242 {
		t.Fatalf("observation domain id = %d, want 4242", got)
	}
}

func TestIPFIXSkipsCollectorTraffic(t *testing.T) {
	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	collectorFlow := exportedFlow(
		collector.FlowKey{
			Ifindex: 1,
			Dir:     1,
			Proto:   17,
			SrcAddr: exp.localAddr,
			DstAddr: exp.collectorAddr,
			SrcPort: exp.localPort,
			DstPort: exp.collectorPort,
		},
		collector.FlowEntry{
			FirstSeen: time.Unix(1_700_000_000, 0).UTC(),
			LastSeen:  time.Unix(1_700_000_000, 0).UTC(),
			Packets:   1,
			IPBytes:   128,
		},
		collector.FlowEndReasonEndOfFlow,
	)

	if err := exp.ExportFlow(collectorFlow); err != nil {
		t.Fatalf("ExportFlow: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	assertNoIPFIXDatagram(t, conn)
}

func TestIPFIXExportsTrafficToCollectorDestinationFromOtherSocket(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	srcPort := exp.localPort + 1
	if srcPort == exp.collectorPort {
		srcPort++
	}

	otherFlow := exportedFlow(
		collector.FlowKey{
			Ifindex: 1,
			Dir:     1,
			Proto:   17,
			SrcAddr: netip.MustParseAddr("::ffff:192.0.2.1"),
			DstAddr: exp.collectorAddr,
			SrcPort: srcPort,
			DstPort: exp.collectorPort,
		},
		collector.FlowEntry{
			FirstSeen: time.Unix(1_700_000_000, 0).UTC(),
			LastSeen:  time.Unix(1_700_000_000, 0).UTC(),
			Packets:   3,
			IPBytes:   384,
		},
		collector.FlowEndReasonEndOfFlow,
	)

	if err := exp.ExportFlow(otherFlow); err != nil {
		t.Fatalf("ExportFlow: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	msg := mustReadIPFIXDatagram(t, conn)
	if got := len(msg.Sets); got != 2 {
		t.Fatalf("set count = %d, want 2", got)
	}

	_, fields := parseTemplateSet(t, msg.Sets[0])
	record := parseDataRecord(t, msg.Sets[1], fields)
	assertIPFIXDataUInt16(t, record, "sourceTransportPort", srcPort)
	assertIPFIXDataUInt16(t, record, "destinationTransportPort", exp.collectorPort)
	assertIPFIXDataUInt64(t, record, "packetDeltaCount", 3)
	assertIPFIXDataUInt64(t, record, "octetDeltaCount", 384)
}

func TestIPFIXUsesConfiguredBindHost(t *testing.T) {
	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	cfg := testIPFIXConfig(addr.IP.String(), addr.Port)
	cfg.Bind = config.IPFIXBindConfig{Host: "127.0.0.1"}
	exp, err := NewIPFIX(cfg, 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	if exp.localAddr != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("localAddr = %s, want 127.0.0.1", exp.localAddr)
	}
	if exp.localPort == 0 {
		t.Fatal("localPort = 0, want ephemeral port")
	}
}

func startIPFIXListener(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	return conn
}

func mustReadIPFIXDatagram(t *testing.T, conn *net.UDPConn) decodedIPFIXMessage {
	t.Helper()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	msg, err := decodeIPFIXMessage(buf[:n])
	if err != nil {
		t.Fatalf("decodeIPFIXMessage: %v", err)
	}
	return msg
}

func assertNoIPFIXDatagram(t *testing.T, conn *net.UDPConn) {
	t.Helper()

	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 2048)
	_, _, err := conn.ReadFromUDP(buf)
	if err == nil {
		t.Fatal("unexpected datagram received")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return
	}
}

func decodeIPFIXMessage(data []byte) (decodedIPFIXMessage, error) {
	if len(data) < 16 {
		return decodedIPFIXMessage{}, fmt.Errorf("short ipfix message")
	}

	msg := decodedIPFIXMessage{
		Version:             binary.BigEndian.Uint16(data[0:2]),
		Length:              binary.BigEndian.Uint16(data[2:4]),
		SequenceNum:         binary.BigEndian.Uint32(data[8:12]),
		ObservationDomainID: binary.BigEndian.Uint32(data[12:16]),
	}
	if int(msg.Length) != len(data) {
		return decodedIPFIXMessage{}, fmt.Errorf("message length = %d, want %d", msg.Length, len(data))
	}

	offset := 16
	for offset < len(data) {
		if offset+4 > len(data) {
			return decodedIPFIXMessage{}, fmt.Errorf("truncated set header")
		}
		setID := binary.BigEndian.Uint16(data[offset : offset+2])
		setLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		if setLen < 4 {
			return decodedIPFIXMessage{}, fmt.Errorf("invalid set length %d", setLen)
		}
		next := offset + int(setLen)
		if next > len(data) {
			return decodedIPFIXMessage{}, fmt.Errorf("set overruns message")
		}
		payload := make([]byte, int(setLen)-4)
		copy(payload, data[offset+4:next])
		msg.Sets = append(msg.Sets, decodedIPFIXSet{
			ID:      setID,
			Payload: payload,
		})
		offset = next
	}

	return msg, nil
}

func parseTemplateSet(t *testing.T, set decodedIPFIXSet) (uint16, []decodedTemplateField) {
	t.Helper()

	if len(set.Payload) < 4 {
		t.Fatalf("short template payload")
	}
	templateID := binary.BigEndian.Uint16(set.Payload[0:2])
	fieldCount := int(binary.BigEndian.Uint16(set.Payload[2:4]))

	fields := make([]decodedTemplateField, 0, fieldCount)
	offset := 4
	for i := range fieldCount {
		if offset+4 > len(set.Payload) {
			t.Fatalf("truncated template field %d", i)
		}
		fieldType := binary.BigEndian.Uint16(set.Payload[offset : offset+2])
		fieldLen := binary.BigEndian.Uint16(set.Payload[offset+2 : offset+4])
		offset += 4

		field := decodedTemplateField{
			ID:     fieldType,
			Length: fieldLen,
		}
		if field.ID&0x8000 != 0 {
			if offset+4 > len(set.Payload) {
				t.Fatalf("truncated enterprise field %d", i)
			}
			field.HasPen = true
			field.ID ^= 0x8000
			field.Pen = binary.BigEndian.Uint32(set.Payload[offset : offset+4])
			offset += 4
		}
		fields = append(fields, field)
	}
	return templateID, fields
}

func assertTemplateFields(t *testing.T, fields []decodedTemplateField, names []string) {
	t.Helper()

	if len(fields) != len(names) {
		t.Fatalf("template field count = %d, want %d", len(fields), len(names))
	}
	for i, name := range names {
		ie, err := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		if err != nil {
			t.Fatalf("GetInfoElement(%q): %v", name, err)
		}
		field := fields[i]
		if field.ID != ie.ElementId {
			t.Fatalf("field %d id = %d, want %d for %s", i, field.ID, ie.ElementId, name)
		}
		if field.Length != ie.Len {
			t.Fatalf("field %d length = %d, want %d for %s", i, field.Length, ie.Len, name)
		}
	}
}

func parseDataRecord(t *testing.T, set decodedIPFIXSet, fields []decodedTemplateField) map[string][]byte {
	t.Helper()

	record := make(map[string][]byte, len(fields))
	offset := 0
	for i, field := range fields {
		next := offset + int(field.Length)
		if next > len(set.Payload) {
			t.Fatalf("data field %d overruns payload", i)
		}
		name := templateFieldName(t, field.ID)
		value := make([]byte, field.Length)
		copy(value, set.Payload[offset:next])
		record[name] = value
		offset = next
	}
	if offset != len(set.Payload) {
		t.Fatalf("unexpected trailing data bytes = %d", len(set.Payload)-offset)
	}
	return record
}

func templateFieldNames(isIPv6 bool) []string {
	if isIPv6 {
		return ipfixFieldNames(ipfixIPv6Fields, ipfixCommonFields)
	}
	return ipfixFieldNames(ipfixIPv4Fields, ipfixCommonFields)
}

func templateFieldName(t *testing.T, id uint16) string {
	t.Helper()

	for _, name := range append(templateFieldNames(false), templateFieldNames(true)...) {
		ie, err := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		if err != nil {
			t.Fatalf("GetInfoElement(%q): %v", name, err)
		}
		if ie.ElementId == id {
			return name
		}
	}
	t.Fatalf("unknown template field id %d", id)
	return ""
}

func assertIPFIXDataIP(t *testing.T, record map[string][]byte, name string, want net.IP) {
	t.Helper()

	got, ok := record[name]
	if !ok {
		t.Fatalf("%s missing from data record", name)
	}
	if !net.IP(got).Equal(want) {
		t.Fatalf("%s = %v, want %v", name, net.IP(got), want)
	}
}

func assertIPFIXDataUInt8(t *testing.T, record map[string][]byte, name string, want uint8) {
	t.Helper()

	got, ok := record[name]
	if !ok {
		t.Fatalf("%s missing from data record", name)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("%s = %d, want %d", name, got[0], want)
	}
}

func assertIPFIXDataUInt16(t *testing.T, record map[string][]byte, name string, want uint16) {
	t.Helper()

	got, ok := record[name]
	if !ok {
		t.Fatalf("%s missing from data record", name)
	}
	if len(got) != 2 || binary.BigEndian.Uint16(got) != want {
		t.Fatalf("%s = %d, want %d", name, binary.BigEndian.Uint16(got), want)
	}
}

func assertIPFIXDataUInt32(t *testing.T, record map[string][]byte, name string, want uint32) {
	t.Helper()

	got, ok := record[name]
	if !ok {
		t.Fatalf("%s missing from data record", name)
	}
	if len(got) != 4 || binary.BigEndian.Uint32(got) != want {
		t.Fatalf("%s = %d, want %d", name, binary.BigEndian.Uint32(got), want)
	}
}

func assertIPFIXDataUInt64(t *testing.T, record map[string][]byte, name string, want uint64) {
	t.Helper()

	got, ok := record[name]
	if !ok {
		t.Fatalf("%s missing from data record", name)
	}
	if len(got) != 8 || binary.BigEndian.Uint64(got) != want {
		t.Fatalf("%s = %d, want %d", name, binary.BigEndian.Uint64(got), want)
	}
}

func assertIPFIXDataFloat64Range(t *testing.T, record map[string][]byte, name string, min, max float64) {
	t.Helper()

	got, ok := record[name]
	if !ok {
		t.Fatalf("%s missing from data record", name)
	}
	if len(got) != 8 {
		t.Fatalf("%s length = %d, want 8", name, len(got))
	}
	value := math.Float64frombits(binary.BigEndian.Uint64(got))
	if value < min || value > max {
		t.Fatalf("%s = %f, want between %f and %f", name, value, min, max)
	}
}

func TestIPFIXTemplateSuppressedWithinRefreshWindow(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	now := time.Unix(1_700_000_000, 0).UTC()
	exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()
	exp.nowFunc = func() time.Time { return now }

	flow := exportedFlow(
		collector.FlowKey{
			Ifindex: 1, Dir: 0, Proto: 6,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			SrcPort: 1234, DstPort: 80,
		},
		collector.FlowEntry{
			FirstSeen: now, LastSeen: now, Packets: 1, IPBytes: 100,
		},
		collector.FlowEndReasonIdleTimeout,
	)

	// first export should include template + data
	if err := exp.ExportFlow(flow); err != nil {
		t.Fatalf("first ExportFlow: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	msg := mustReadIPFIXDatagram(t, conn)
	if got := len(msg.Sets); got != 2 {
		t.Fatalf("first export set count = %d, want 2 (template + data)", got)
	}

	// second export within refresh window should have data only
	now = now.Add(1 * time.Second)
	if err := exp.ExportFlow(flow); err != nil {
		t.Fatalf("second ExportFlow: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	msg = mustReadIPFIXDatagram(t, conn)
	if got := len(msg.Sets); got != 1 {
		t.Fatalf("second export set count = %d, want 1 (data only)", got)
	}
	if msg.Sets[0].ID == entitiesTemplateSetID {
		t.Fatal("second export should not contain a template set")
	}
}

func TestIPFIXTemplateResendAfterRefreshTimeout(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	now := time.Unix(1_700_000_000, 0).UTC()
	exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()
	exp.nowFunc = func() time.Time { return now }

	flow := exportedFlow(
		collector.FlowKey{
			Ifindex: 1, Dir: 0, Proto: 6,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			SrcPort: 1234, DstPort: 80,
		},
		collector.FlowEntry{
			FirstSeen: now, LastSeen: now, Packets: 1, IPBytes: 100,
		},
		collector.FlowEndReasonIdleTimeout,
	)

	// first export includes template
	if err := exp.ExportFlow(flow); err != nil {
		t.Fatalf("first ExportFlow: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	_ = mustReadIPFIXDatagram(t, conn)

	// advance past the refresh timeout
	now = now.Add(exp.templateRefreshTimeout + 1*time.Second)
	if err := exp.ExportFlow(flow); err != nil {
		t.Fatalf("refresh ExportFlow: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	msg := mustReadIPFIXDatagram(t, conn)
	if got := len(msg.Sets); got != 2 {
		t.Fatalf("refresh export set count = %d, want 2 (template + data)", got)
	}
	if msg.Sets[0].ID != entitiesTemplateSetID {
		t.Fatalf("refresh export first set id = %d, want %d", msg.Sets[0].ID, entitiesTemplateSetID)
	}
}

func TestIPFIXSendsTemplatesFirstOnANewSocket(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	now := time.Unix(1_700_000_000, 0).UTC()
	exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()
	exp.nowFunc = func() time.Time { return now }

	send := func() decodedIPFIXMessage {
		t.Helper()
		if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", 1, now)); err != nil {
			t.Fatalf("ExportFlow: %v", err)
		}
		if err := exp.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		return mustReadIPFIXDatagram(t, conn)
	}
	if msg := send(); len(msg.Sets) != 2 {
		t.Fatalf("first message has %d sets, want template and data", len(msg.Sets))
	}

	// an unusable socket was closed, the next batch dials a new one from
	// another source port, a new transport session that has seen no
	// template yet
	exp.mu.Lock()
	_ = exp.conn.Close()
	exp.conn = nil
	exp.nextDial = time.Time{}
	exp.mu.Unlock()

	now = now.Add(time.Second)
	msg := send()
	var ids []uint16
	for _, set := range msg.Sets {
		ids = append(ids, set.ID)
	}
	if len(ids) != 2 || ids[0] != entitiesTemplateSetID {
		t.Fatalf("first message on the new socket has set ids %v, want the template first", ids)
	}
}

const entitiesTemplateSetID uint16 = 2

// exportedFlow builds the record the collector sends for one interval of the
// flow key, with the times and counters of e
func exportedFlow(key collector.FlowKey, e collector.FlowEntry, reason uint8) collector.ExportedFlow {
	return collector.ExportedFlow{
		SrcAddr:    key.SrcAddr.As16(),
		DstAddr:    key.DstAddr.As16(),
		Start:      e.FirstSeen.UnixNano(),
		End:        e.LastSeen.UnixNano(),
		Packets:    e.Packets,
		Octets:     e.IPBytes,
		EstPackets: e.EstPackets,
		Ifindex:    key.Ifindex,
		SrcPort:    key.SrcPort,
		DstPort:    key.DstPort,
		Dir:        key.Dir,
		Proto:      key.Proto,
		EndReason:  reason,
	}
}

func testFlow(src, dst string, port uint16, now time.Time) collector.ExportedFlow {
	return exportedFlow(
		collector.FlowKey{
			Ifindex: 1, Dir: 0, Proto: 6,
			SrcAddr: netip.MustParseAddr(src),
			DstAddr: netip.MustParseAddr(dst),
			SrcPort: port, DstPort: 443,
		},
		collector.FlowEntry{
			FirstSeen: now, LastSeen: now, Packets: 2, IPBytes: 300,
		},
		collector.FlowEndReasonIdleTimeout,
	)
}

func TestIPFIXPacksRecordsIntoOneMessage(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	for port := uint16(1); port <= 5; port++ {
		if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", port, now)); err != nil {
			t.Fatalf("ExportFlow: %v", err)
		}
	}
	for port := uint16(1); port <= 2; port++ {
		if err := exp.ExportFlow(testFlow("2001:db8::1", "2001:db8::2", port, now)); err != nil {
			t.Fatalf("ExportFlow: %v", err)
		}
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// both templates and both data sets travel in one datagram
	msg := mustReadIPFIXDatagram(t, conn)
	if got := len(msg.Sets); got != 4 {
		t.Fatalf("set count = %d, want 4 (two templates, two data sets)", got)
	}
	if msg.Sets[0].ID != entitiesTemplateSetID || msg.Sets[1].ID != entitiesTemplateSetID {
		t.Fatalf("set ids = %d %d, want two template sets first", msg.Sets[0].ID, msg.Sets[1].ID)
	}
	if msg.Sets[2].ID != 256 || msg.Sets[3].ID != 257 {
		t.Fatalf("data set ids = %d %d, want 256 and 257", msg.Sets[2].ID, msg.Sets[3].ID)
	}
	if got := len(msg.Sets[2].Payload) / exp.ipv4.recordLen; got != 5 {
		t.Fatalf("ipv4 records = %d, want 5", got)
	}
	if got := len(msg.Sets[3].Payload) / exp.ipv6.recordLen; got != 2 {
		t.Fatalf("ipv6 records = %d, want 2", got)
	}
	if msg.SequenceNum != 0 {
		t.Fatalf("sequence = %d, want 0 for the first message", msg.SequenceNum)
	}
	assertNoIPFIXDatagram(t, conn)

	// the next message continues the sequence by the records sent so far
	if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", 9, now)); err != nil {
		t.Fatalf("ExportFlow: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	msg = mustReadIPFIXDatagram(t, conn)
	if msg.SequenceNum != 7 {
		t.Fatalf("sequence = %d, want 7", msg.SequenceNum)
	}
	if got := len(msg.Sets); got != 1 {
		t.Fatalf("set count = %d, want 1 (data only inside the template refresh window)", got)
	}

	stats := exp.Stats()
	if stats.Messages != 2 || stats.Records != 8 {
		t.Fatalf("stats = %d messages %d records, want 2 and 8", stats.Messages, stats.Records)
	}
}

func TestIPFIXSplitsMessagesAtMaxSize(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	cfg := testIPFIXConfig(addr.IP.String(), addr.Port)
	// room for the template and one record, then two records per message
	cfg.MaxMessageSize = 200
	exp, err := NewIPFIX(cfg, 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	for port := uint16(1); port <= 5; port++ {
		if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", port, now)); err != nil {
			t.Fatalf("ExportFlow: %v", err)
		}
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	var records int
	for i := range 3 {
		msg := mustReadIPFIXDatagram(t, conn)
		if int(msg.Length) > cfg.MaxMessageSize {
			t.Fatalf("message %d is %d bytes, want <= %d", i, msg.Length, cfg.MaxMessageSize)
		}
		if i == 0 && msg.Sets[0].ID != entitiesTemplateSetID {
			t.Fatal("first message must carry the template")
		}
		for _, set := range msg.Sets {
			if set.ID == 256 {
				records += len(set.Payload) / exp.ipv4.recordLen
			}
		}
	}
	assertNoIPFIXDatagram(t, conn)
	if records != 5 {
		t.Fatalf("records across messages = %d, want 5", records)
	}
}

func TestIPFIXQueueFullDropsRecords(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	cfg := testIPFIXConfig(addr.IP.String(), addr.Port)
	cfg.QueueSize = 2
	exp, err := NewIPFIX(cfg, 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	// park the sender inside a dial so the queue fills behind it
	release := make(chan struct{})
	exp.mu.Lock()
	_ = exp.conn.Close()
	exp.conn = nil
	exp.nextDial = time.Time{}
	exp.dial = func(local, remote *net.UDPAddr) (*net.UDPConn, error) {
		<-release
		return net.DialUDP("udp", local, remote)
	}
	exp.mu.Unlock()

	now := time.Unix(1_700_000_000, 0).UTC()
	if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", 1, now)); err != nil {
		t.Fatalf("ExportFlow: %v", err)
	}
	flushed := make(chan error, 1)
	go func() { flushed <- exp.Flush() }()

	// wait until the sender is parked in the dial
	deadline := time.Now().Add(2 * time.Second)
	for exp.Stats().Dials < 2 {
		if time.Now().After(deadline) {
			t.Fatal("sender never reached the dial")
		}
		time.Sleep(5 * time.Millisecond)
	}

	var refused int
	for port := uint16(2); port <= 5; port++ {
		if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", port, now)); err != nil {
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("refused = %d, want 2 with a queue of 2", refused)
	}
	if got := exp.Stats().QueueDropped; got != 2 {
		t.Fatalf("queue dropped = %d, want 2", got)
	}

	close(release)
	if err := <-flushed; err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := exp.Stats().Records; got != 3 {
		t.Fatalf("records sent = %d, want 3", got)
	}
}

func TestIPFIXRefusesRecordsOnceClosed(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	if err := exp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// nothing drains the queue any more, a record queued now is lost
	if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", 1, time.Now())); err == nil {
		t.Fatal("ExportFlow after Close succeeded")
	}
	if got := exp.Stats().Unsent; got != 1 {
		t.Fatalf("unsent = %d, want the refused record counted", got)
	}
	if got := len(exp.queue); got != 0 {
		t.Fatalf("queue holds %d records after Close, want none", got)
	}
}

func TestIPFIXCountsRecordsLostWithFailedMessages(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	// the socket can send no more, every send fails with EPIPE, which closes
	// it and schedules a re-dial
	raw, err := exp.conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var shutErr error
	if err := raw.Control(func(fd uintptr) { shutErr = unix.Shutdown(int(fd), unix.SHUT_WR) }); err != nil || shutErr != nil {
		t.Fatalf("shutdown: %v %v", err, shutErr)
	}

	// three messages worth of records in one batch
	now := time.Unix(1_700_000_000, 0).UTC()
	for port := uint16(1); port <= 45; port++ {
		if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", port, now)); err != nil {
			t.Fatalf("ExportFlow: %v", err)
		}
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// the first message fails and takes its records with it, the rest of the
	// batch has no socket left and is not tried
	s := exp.Stats()
	if len(s.SendErrors) != 1 || s.SendErrors["EPIPE"] != 1 {
		t.Fatalf("send errors = %v, want one failed message with EPIPE", s.SendErrors)
	}
	if s.SendFailed == 0 || s.Unsent == 0 || s.SendFailed+s.Unsent != 45 {
		t.Fatalf("records lost with the message = %d, unsent = %d, want the 45 split between them", s.SendFailed, s.Unsent)
	}
	if s.Records != 0 || s.Failures() != 45 {
		t.Fatalf("records sent = %d, failures = %d, want 0 and every one of the 45 lost", s.Records, s.Failures())
	}
}

func TestIPFIXCountsSendErrorsByErrno(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	exp, err := NewIPFIX(testIPFIXConfig(addr.IP.String(), addr.Port), 1)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	// nobody listens any more, the port unreachable comes back as
	// ECONNREFUSED on a later send of the connected socket
	_ = conn.Close()

	now := time.Unix(1_700_000_000, 0).UTC()
	deadline := time.Now().Add(3 * time.Second)
	for exp.Stats().SendErrors["ECONNREFUSED"] == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no ECONNREFUSED counted, stats = %+v", exp.Stats())
		}
		if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", 1, now)); err != nil {
			t.Fatalf("ExportFlow: %v", err)
		}
		if err := exp.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// an icmp error keeps the socket, only unreachable networks re-dial
	if !exp.Stats().Connected {
		t.Fatal("exporter dropped the socket on ECONNREFUSED")
	}
}

func TestIPFIXDialsLazily(t *testing.T) {
	loadIPFIXRegistry.Do(registry.LoadRegistry)

	conn := startIPFIXListener(t)
	addr := conn.LocalAddr().(*net.UDPAddr)

	cfg := testIPFIXConfig(addr.IP.String(), addr.Port)
	// a bind address this host does not have, like a tunnel address
	// that shows up after boot
	cfg.Bind = config.IPFIXBindConfig{Host: "192.0.2.123"}
	exp, err := NewIPFIX(cfg, 1)
	if err != nil {
		t.Fatalf("NewIPFIX must not fail on an absent bind address: %v", err)
	}
	defer exp.Close()

	stats := exp.Stats()
	if stats.Connected || stats.DialErrors != 1 {
		t.Fatalf("stats after failed dial = %+v, want disconnected with one dial error", stats)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", 1, now)); err != nil {
		t.Fatalf("ExportFlow: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := exp.Stats().Unsent; got != 1 {
		t.Fatalf("unsent = %d, want 1 while the retry backoff runs", got)
	}
	assertNoIPFIXDatagram(t, conn)

	// the address appears, the next batch dials and goes out
	exp.mu.Lock()
	exp.localBind = nil
	exp.nextDial = time.Time{}
	exp.mu.Unlock()

	if err := exp.ExportFlow(testFlow("::ffff:10.0.0.1", "::ffff:10.0.0.2", 2, now)); err != nil {
		t.Fatalf("ExportFlow: %v", err)
	}
	if err := exp.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	msg := mustReadIPFIXDatagram(t, conn)
	if got := len(msg.Sets); got != 2 {
		t.Fatalf("set count = %d, want template and data", got)
	}
	if !exp.Stats().Connected {
		t.Fatal("exporter not connected after the address appeared")
	}
}
