package export

import (
	"fmt"
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"ysun.co/rfm/collector"
)

var (
	descIfaceRxBytes = prometheus.NewDesc(
		"rfm_interface_rx_bytes_total",
		"Total bytes received on an interface.",
		[]string{"ifname", "proto"}, nil,
	)
	descIfaceTxBytes = prometheus.NewDesc(
		"rfm_interface_tx_bytes_total",
		"Total bytes transmitted on an interface.",
		[]string{"ifname", "proto"}, nil,
	)
	descIfaceRxPackets = prometheus.NewDesc(
		"rfm_interface_rx_packets_total",
		"Total packets received on an interface.",
		[]string{"ifname", "proto"}, nil,
	)
	descIfaceTxPackets = prometheus.NewDesc(
		"rfm_interface_tx_packets_total",
		"Total packets transmitted on an interface.",
		[]string{"ifname", "proto"}, nil,
	)

	descFlowBytes = prometheus.NewDesc(
		"rfm_flow_bytes",
		"Current byte count for an active flow.",
		[]string{"ifname", "direction", "proto", "src_asn", "dst_asn", "src_city", "dst_city"}, nil,
	)
	descFlowPackets = prometheus.NewDesc(
		"rfm_flow_packets",
		"Current packet count for an active flow.",
		[]string{"ifname", "direction", "proto", "src_asn", "dst_asn", "src_city", "dst_city"}, nil,
	)

	descActiveFlows = prometheus.NewDesc(
		"rfm_collector_active_flows",
		"Number of active flows in the collector.",
		nil, nil,
	)
	descEventsTotal = prometheus.NewDesc(
		"rfm_collector_events_total",
		"Total flow events received by the collector.",
		nil, nil,
	)
	descDroppedEvents = prometheus.NewDesc(
		"rfm_collector_dropped_events_total",
		"Total flow events dropped by the ring buffer.",
		nil, nil,
	)
	descForcedEvictions = prometheus.NewDesc(
		"rfm_collector_forced_evictions_total",
		"Total flows forcibly evicted due to table overflow.",
		nil, nil,
	)

	allDescs = []*prometheus.Desc{
		descIfaceRxBytes,
		descIfaceTxBytes,
		descIfaceRxPackets,
		descIfaceTxPackets,
		descFlowBytes,
		descFlowPackets,
		descActiveFlows,
		descEventsTotal,
		descDroppedEvents,
		descForcedEvictions,
	}
)

// MetricsCollector implements prometheus.Collector, reading BPF iface
// stats and the collector's flow table at scrape time.
type MetricsCollector struct {
	source IfaceStatsSource
	col    *collector.Collector
}

// New creates a MetricsCollector. Both source and c may be nil.
func New(source IfaceStatsSource, c *collector.Collector) *MetricsCollector {
	return &MetricsCollector{
		source: source,
		col:    c,
	}
}

// Describe sends all metric descriptors to ch.
func (mc *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range allDescs {
		ch <- d
	}
}

// Collect sends all current metric values to ch.
func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	mc.collectIfaceStats(ch)
	mc.collectFlows(ch)
	mc.collectHealth(ch)
}

func (mc *MetricsCollector) collectIfaceStats(ch chan<- prometheus.Metric) {
	if mc.source == nil {
		return
	}

	for _, e := range mc.source.IfaceStats() {
		ifname := ifnameFromIndex(e.Ifindex)
		proto := strconv.FormatUint(uint64(e.Proto), 10)

		if e.Dir == 0 { // ingress / rx
			ch <- prometheus.MustNewConstMetric(descIfaceRxBytes, prometheus.CounterValue, float64(e.Bytes), ifname, proto)
			ch <- prometheus.MustNewConstMetric(descIfaceRxPackets, prometheus.CounterValue, float64(e.Packets), ifname, proto)
		} else { // egress / tx
			ch <- prometheus.MustNewConstMetric(descIfaceTxBytes, prometheus.CounterValue, float64(e.Bytes), ifname, proto)
			ch <- prometheus.MustNewConstMetric(descIfaceTxPackets, prometheus.CounterValue, float64(e.Packets), ifname, proto)
		}
	}
}

func (mc *MetricsCollector) collectFlows(ch chan<- prometheus.Metric) {
	// TODO: implement flow gauge collection
}

func (mc *MetricsCollector) collectHealth(ch chan<- prometheus.Metric) {
	if mc.col == nil {
		return
	}

	stats := mc.col.Stats()
	ch <- prometheus.MustNewConstMetric(descActiveFlows, prometheus.GaugeValue, float64(stats.ActiveFlows))
	ch <- prometheus.MustNewConstMetric(descEventsTotal, prometheus.CounterValue, float64(stats.TotalEvents))
	ch <- prometheus.MustNewConstMetric(descDroppedEvents, prometheus.CounterValue, float64(stats.DroppedEvents))
	ch <- prometheus.MustNewConstMetric(descForcedEvictions, prometheus.CounterValue, float64(stats.ForcedEvictions))
}

// ifnameFromIndex resolves an interface index to a name, falling back
// to the string representation of the index.
func ifnameFromIndex(ifindex uint32) string {
	iface, err := net.InterfaceByIndex(int(ifindex))
	if err != nil {
		return fmt.Sprintf("%d", ifindex)
	}
	return iface.Name
}

// dirString returns the human-readable direction label.
func dirString(dir uint8) string {
	if dir == 0 {
		return "ingress"
	}
	return "egress"
}

// formatASN formats an ASN as a string, returning empty string for zero.
func formatASN(asn uint32) string {
	if asn == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(asn), 10)
}
