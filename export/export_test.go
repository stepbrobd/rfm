package export

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"ysun.co/rfm/collector"
)

// --- mock types ---

type mockIfaceStats struct {
	entries []IfaceStatsEntry
	err     error
}

func (m *mockIfaceStats) IfaceStats() ([]IfaceStatsEntry, error) {
	return m.entries, m.err
}

type staticEnricher struct {
	srcASN  uint32
	srcCity string
	dstASN  uint32
	dstCity string
}

func (e *staticEnricher) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	return collector.Labels{ASN: e.srcASN, City: e.srcCity},
		collector.Labels{ASN: e.dstASN, City: e.dstCity}
}

// --- test helpers ---

// collectAll calls Collect and returns a map of metric name -> summed value.
func collectAll(t *testing.T, mc *MetricsCollector) map[string]float64 {
	t.Helper()
	metrics := collectMetrics(t, mc)
	result := make(map[string]float64)
	for _, m := range metrics {
		d := new(dto.Metric)
		if err := m.Write(d); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		name := extractName(m.Desc())
		var val float64
		switch {
		case d.Counter != nil:
			val = d.Counter.GetValue()
		case d.Gauge != nil:
			val = d.Gauge.GetValue()
		}
		result[name] += val
	}
	return result
}

// collectMetrics calls Collect and returns all emitted metrics.
func collectMetrics(t *testing.T, mc *MetricsCollector) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 100)
	mc.Collect(ch)
	close(ch)
	var out []prometheus.Metric
	for m := range ch {
		out = append(out, m)
	}
	return out
}

// extractName parses fqName from Desc.String() format: Desc{fqName: "rfm_...", ...}
func extractName(desc *prometheus.Desc) string {
	s := desc.String()
	const prefix = "fqName: \""
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	s = s[i+len(prefix):]
	j := strings.Index(s, "\"")
	if j < 0 {
		return ""
	}
	return s[:j]
}

// assertCounter checks that the named metric has the expected value.
func assertCounter(t *testing.T, vals map[string]float64, name string, want float64) {
	t.Helper()
	got, ok := vals[name]
	if !ok {
		t.Errorf("metric %q not found", name)
		return
	}
	if got != want {
		t.Errorf("%s = %g, want %g", name, got, want)
	}
}

// assertGauge checks that the named metric has the expected value.
func assertGauge(t *testing.T, vals map[string]float64, name string, want float64) {
	t.Helper()
	got, ok := vals[name]
	if !ok {
		t.Errorf("metric %q not found", name)
		return
	}
	if got != want {
		t.Errorf("%s = %g, want %g", name, got, want)
	}
}

// metricLabels returns the label name->value map for a metric.
func metricLabels(t *testing.T, m prometheus.Metric) map[string]string {
	t.Helper()
	d := new(dto.Metric)
	if err := m.Write(d); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	labels := make(map[string]string)
	for _, lp := range d.Label {
		labels[lp.GetName()] = lp.GetValue()
	}
	return labels
}

// metricValue returns the numeric value of a metric (counter or gauge).
func metricValue(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	d := new(dto.Metric)
	if err := m.Write(d); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	switch {
	case d.Counter != nil:
		return d.Counter.GetValue()
	case d.Gauge != nil:
		return d.Gauge.GetValue()
	}
	return 0
}

// --- tests ---

func TestMetricsCollectorImplementsInterface(t *testing.T) {
	var _ prometheus.Collector = (*MetricsCollector)(nil)
}

func TestDescribe(t *testing.T) {
	mc := New(nil, nil)
	ch := make(chan *prometheus.Desc, 20)
	mc.Describe(ch)
	close(ch)

	var descs []*prometheus.Desc
	for d := range ch {
		descs = append(descs, d)
	}

	if got := len(descs); got != 10 {
		t.Fatalf("got %d descriptors, want 10", got)
	}

	names := make(map[string]bool)
	for _, d := range descs {
		names[extractName(d)] = true
	}

	want := []string{
		"rfm_interface_rx_bytes_total",
		"rfm_interface_tx_bytes_total",
		"rfm_interface_rx_packets_total",
		"rfm_interface_tx_packets_total",
		"rfm_flow_bytes",
		"rfm_flow_packets",
		"rfm_collector_active_flows",
		"rfm_collector_events_total",
		"rfm_collector_dropped_events_total",
		"rfm_collector_forced_evictions_total",
	}
	for _, w := range want {
		if !names[w] {
			t.Errorf("missing descriptor %q", w)
		}
	}
}

func TestCollectHealth(t *testing.T) {
	c := collector.New(time.Minute, nil, 0)
	c.Record(collector.FlowEvent{
		Ifindex: 1,
		Dir:     0,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("10.0.0.1"),
		DstAddr: netip.MustParseAddr("10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
		Len:     100,
	}, time.Now())

	mc := New(nil, c)
	vals := collectAll(t, mc)

	assertGauge(t, vals, "rfm_collector_active_flows", 1)
	assertCounter(t, vals, "rfm_collector_events_total", 1)
	assertCounter(t, vals, "rfm_collector_dropped_events_total", 0)
	assertCounter(t, vals, "rfm_collector_forced_evictions_total", 0)
}

func TestCollectIfaceStats(t *testing.T) {
	src := &mockIfaceStats{
		entries: []IfaceStatsEntry{
			{Ifindex: 1, Dir: 0, Proto: 4, Packets: 10, Bytes: 1000}, // rx ipv4
			{Ifindex: 1, Dir: 1, Proto: 4, Packets: 5, Bytes: 500},   // tx ipv4
			{Ifindex: 1, Dir: 0, Proto: 6, Packets: 3, Bytes: 300},   // rx ipv6
		},
	}

	mc := New(src, nil)
	vals := collectAll(t, mc)

	assertCounter(t, vals, "rfm_interface_rx_bytes_total", 1300) // 1000 + 300
	assertCounter(t, vals, "rfm_interface_tx_bytes_total", 500)
	assertCounter(t, vals, "rfm_interface_rx_packets_total", 13) // 10 + 3
	assertCounter(t, vals, "rfm_interface_tx_packets_total", 5)
}

func TestCollectFlowsNoEnricher(t *testing.T) {
	c := collector.New(time.Minute, nil, 0)
	c.Record(collector.FlowEvent{
		Ifindex: 2,
		Dir:     0,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("192.168.1.1"),
		DstAddr: netip.MustParseAddr("192.168.1.2"),
		SrcPort: 1234,
		DstPort: 443,
		Len:     200,
	}, time.Now())

	mc := New(nil, c)
	vals := collectAll(t, mc)

	assertGauge(t, vals, "rfm_flow_bytes", 200)
	assertGauge(t, vals, "rfm_flow_packets", 1)

	// Check labels - enrichment should be empty strings
	metrics := collectMetrics(t, mc)
	for _, m := range metrics {
		name := extractName(m.Desc())
		if name != "rfm_flow_bytes" {
			continue
		}
		labels := metricLabels(t, m)
		if labels["src_asn"] != "" {
			t.Errorf("src_asn = %q, want empty", labels["src_asn"])
		}
		if labels["dst_asn"] != "" {
			t.Errorf("dst_asn = %q, want empty", labels["dst_asn"])
		}
		if labels["direction"] != "ingress" {
			t.Errorf("direction = %q, want ingress", labels["direction"])
		}
	}
}

func TestCollectFlowsWithEnricher(t *testing.T) {
	e := &staticEnricher{
		srcASN: 64512, srcCity: "Berlin",
		dstASN: 13335, dstCity: "London",
	}
	c := collector.New(time.Minute, e, 0)
	c.Record(collector.FlowEvent{
		Ifindex: 3,
		Dir:     1,
		Proto:   17,
		SrcAddr: netip.MustParseAddr("10.1.0.1"),
		DstAddr: netip.MustParseAddr("10.2.0.1"),
		SrcPort: 5000,
		DstPort: 53,
		Len:     64,
	}, time.Now())

	mc := New(nil, c)
	metrics := collectMetrics(t, mc)

	var found bool
	for _, m := range metrics {
		name := extractName(m.Desc())
		if name != "rfm_flow_bytes" {
			continue
		}
		found = true
		labels := metricLabels(t, m)

		if labels["src_asn"] != "64512" {
			t.Errorf("src_asn = %q, want 64512", labels["src_asn"])
		}
		if labels["dst_asn"] != "13335" {
			t.Errorf("dst_asn = %q, want 13335", labels["dst_asn"])
		}
		if labels["src_city"] != "Berlin" {
			t.Errorf("src_city = %q, want Berlin", labels["src_city"])
		}
		if labels["dst_city"] != "London" {
			t.Errorf("dst_city = %q, want London", labels["dst_city"])
		}
		if labels["direction"] != "egress" {
			t.Errorf("direction = %q, want egress", labels["direction"])
		}

		val := metricValue(t, m)
		if val != 64 {
			t.Errorf("flow_bytes = %g, want 64", val)
		}
	}
	if !found {
		t.Error("rfm_flow_bytes metric not found")
	}
}

func TestCollectNilSources(t *testing.T) {
	mc := New(nil, nil)
	// Must not panic
	vals := collectAll(t, mc)
	// Should have no iface or flow metrics, but also no panic
	_ = vals
}

func TestCollectFlowsAggregatesDuplicateLabels(t *testing.T) {
	// two flows with different ports but same exported labels
	// must produce one aggregated metric, not duplicate series
	c := collector.New(time.Minute, nil, 0)
	now := time.Now()
	c.Record(collector.FlowEvent{
		Ifindex: 1, Dir: 0, Proto: 6,
		SrcAddr: netip.MustParseAddr("10.0.0.1"),
		DstAddr: netip.MustParseAddr("10.0.0.2"),
		SrcPort: 1000, DstPort: 80, Len: 100,
	}, now)
	c.Record(collector.FlowEvent{
		Ifindex: 1, Dir: 0, Proto: 6,
		SrcAddr: netip.MustParseAddr("10.0.0.1"),
		DstAddr: netip.MustParseAddr("10.0.0.2"),
		SrcPort: 2000, DstPort: 80, Len: 200,
	}, now)

	mc := New(nil, c)

	// use a real registry to verify no duplicate series
	reg := prometheus.NewRegistry()
	reg.MustRegister(mc)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	// find rfm_flow_bytes and check it has exactly one series
	for _, mf := range mfs {
		if mf.GetName() != "rfm_flow_bytes" {
			continue
		}
		if got := len(mf.GetMetric()); got != 1 {
			t.Fatalf("rfm_flow_bytes series count = %d, want 1 (aggregated)", got)
		}
		val := mf.GetMetric()[0].GetGauge().GetValue()
		if val != 300 {
			t.Fatalf("rfm_flow_bytes = %g, want 300 (100+200)", val)
		}
	}
}

func TestCollectIfaceStatsError(t *testing.T) {
	src := &mockIfaceStats{
		entries: []IfaceStatsEntry{
			{Ifindex: 1, Dir: 0, Proto: 4, Packets: 10, Bytes: 1000},
		},
		err: fmt.Errorf("map iteration failed"),
	}

	mc := New(src, nil)
	metrics := collectMetrics(t, mc)

	// on error, no iface metrics should be emitted
	for _, m := range metrics {
		name := extractName(m.Desc())
		if strings.HasPrefix(name, "rfm_interface_") {
			t.Errorf("unexpected iface metric %q on error", name)
		}
	}
}

func TestCollectIfaceStatsFamily(t *testing.T) {
	// iface stats proto=4 is IPv4, proto=6 is IPv6
	// the label should be "family" with values "ipv4" / "ipv6"
	src := &mockIfaceStats{
		entries: []IfaceStatsEntry{
			{Ifindex: 1, Dir: 0, Proto: 4, Packets: 10, Bytes: 1000},
			{Ifindex: 1, Dir: 0, Proto: 6, Packets: 5, Bytes: 500},
		},
	}

	mc := New(src, nil)
	metrics := collectMetrics(t, mc)

	families := make(map[string]bool)
	for _, m := range metrics {
		name := extractName(m.Desc())
		if name != "rfm_interface_rx_bytes_total" {
			continue
		}
		labels := metricLabels(t, m)
		families[labels["family"]] = true
	}

	if !families["ipv4"] {
		t.Error("expected family=ipv4 label")
	}
	if !families["ipv6"] {
		t.Error("expected family=ipv6 label")
	}
}
