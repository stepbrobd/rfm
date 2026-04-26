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

			c := collector.New(10*time.Second, nil, 0)
			c.SetFlowExporter(exp)

			t0 := time.Unix(1_700_000_000, 0).UTC()
			ev := collector.FlowEvent{
				Ifindex: 7,
				Dir:     0,
				Proto:   17,
				SrcAddr: tc.src,
				DstAddr: tc.dst,
				SrcPort: 12345,
				DstPort: 53,
				Len:     512,
			}
			c.Record(ev, t0)
			c.Evict(t0.Add(11 * time.Second))

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
	flow := collector.ExportedFlow{
		Key: collector.FlowKey{
			Ifindex: 1, Dir: 0, Proto: 6,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			SrcPort: 1234, DstPort: 80,
		},
		Entry: collector.FlowEntry{
			FirstSeen: now, LastSeen: now, Packets: 1, Bytes: 100,
		},
		EndReason: collector.FlowEndReasonIdleTimeout,
	}

	if err := exp.ExportFlow(flow); err != nil {
		t.Fatalf("ExportFlow: %v", err)
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

	collectorFlow := collector.ExportedFlow{
		Key: collector.FlowKey{
			Ifindex: 1,
			Dir:     1,
			Proto:   17,
			SrcAddr: exp.localAddr,
			DstAddr: exp.collectorAddr,
			SrcPort: exp.localPort,
			DstPort: exp.collectorPort,
		},
		Entry: collector.FlowEntry{
			FirstSeen: time.Unix(1_700_000_000, 0).UTC(),
			LastSeen:  time.Unix(1_700_000_000, 0).UTC(),
			Packets:   1,
			Bytes:     128,
		},
		EndReason: collector.FlowEndReasonEndOfFlow,
	}

	if err := exp.ExportFlow(collectorFlow); err != nil {
		t.Fatalf("ExportFlow: %v", err)
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

	otherFlow := collector.ExportedFlow{
		Key: collector.FlowKey{
			Ifindex: 1,
			Dir:     1,
			Proto:   17,
			SrcAddr: netip.MustParseAddr("::ffff:192.0.2.1"),
			DstAddr: exp.collectorAddr,
			SrcPort: srcPort,
			DstPort: exp.collectorPort,
		},
		Entry: collector.FlowEntry{
			FirstSeen: time.Unix(1_700_000_000, 0).UTC(),
			LastSeen:  time.Unix(1_700_000_000, 0).UTC(),
			Packets:   3,
			Bytes:     384,
		},
		EndReason: collector.FlowEndReasonEndOfFlow,
	}

	if err := exp.ExportFlow(otherFlow); err != nil {
		t.Fatalf("ExportFlow: %v", err)
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

	flow := collector.ExportedFlow{
		Key: collector.FlowKey{
			Ifindex: 1, Dir: 0, Proto: 6,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			SrcPort: 1234, DstPort: 80,
		},
		Entry: collector.FlowEntry{
			FirstSeen: now, LastSeen: now, Packets: 1, Bytes: 100,
		},
		EndReason: collector.FlowEndReasonIdleTimeout,
	}

	// first export should include template + data
	if err := exp.ExportFlow(flow); err != nil {
		t.Fatalf("first ExportFlow: %v", err)
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

	flow := collector.ExportedFlow{
		Key: collector.FlowKey{
			Ifindex: 1, Dir: 0, Proto: 6,
			SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
			DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
			SrcPort: 1234, DstPort: 80,
		},
		Entry: collector.FlowEntry{
			FirstSeen: now, LastSeen: now, Packets: 1, Bytes: 100,
		},
		EndReason: collector.FlowEndReasonIdleTimeout,
	}

	// first export includes template
	if err := exp.ExportFlow(flow); err != nil {
		t.Fatalf("first ExportFlow: %v", err)
	}
	_ = mustReadIPFIXDatagram(t, conn)

	// advance past the refresh timeout
	now = now.Add(exp.templateRefreshTimeout + 1*time.Second)
	if err := exp.ExportFlow(flow); err != nil {
		t.Fatalf("refresh ExportFlow: %v", err)
	}
	msg := mustReadIPFIXDatagram(t, conn)
	if got := len(msg.Sets); got != 2 {
		t.Fatalf("refresh export set count = %d, want 2 (template + data)", got)
	}
	if msg.Sets[0].ID != entitiesTemplateSetID {
		t.Fatalf("refresh export first set id = %d, want %d", msg.Sets[0].ID, entitiesTemplateSetID)
	}
}

const entitiesTemplateSetID uint16 = 2
