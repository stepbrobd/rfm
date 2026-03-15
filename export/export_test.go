package export

import (
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
}

func (m *mockIfaceStats) IfaceStats() []IfaceStatsEntry {
	return m.entries
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
			{Ifindex: 1, Dir: 0, Proto: 6, Packets: 10, Bytes: 1000},  // rx
			{Ifindex: 1, Dir: 1, Proto: 6, Packets: 5, Bytes: 500},    // tx
			{Ifindex: 1, Dir: 0, Proto: 17, Packets: 3, Bytes: 300},   // rx udp
		},
	}

	mc := New(src, nil)
	vals := collectAll(t, mc)

	assertCounter(t, vals, "rfm_interface_rx_bytes_total", 1300)   // 1000 + 300
	assertCounter(t, vals, "rfm_interface_tx_bytes_total", 500)
	assertCounter(t, vals, "rfm_interface_rx_packets_total", 13)   // 10 + 3
	assertCounter(t, vals, "rfm_interface_tx_packets_total", 5)
}

func TestCollectNilSources(t *testing.T) {
	mc := New(nil, nil)
	// Must not panic
	vals := collectAll(t, mc)
	// Should have no iface or flow metrics, but also no panic
	_ = vals
}
