package export

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/prometheus/client_golang/prometheus"
	"ysun.co/rfm/collector"
)

var (
	descIfaceRxBytes = prometheus.NewDesc(
		"rfm_interface_rx_bytes_total",
		"Total bytes received on an interface.",
		[]string{"ifname", "family"}, nil,
	)
	descIfaceTxBytes = prometheus.NewDesc(
		"rfm_interface_tx_bytes_total",
		"Total bytes transmitted on an interface.",
		[]string{"ifname", "family"}, nil,
	)
	descIfaceRxPackets = prometheus.NewDesc(
		"rfm_interface_rx_packets_total",
		"Total packets received on an interface.",
		[]string{"ifname", "family"}, nil,
	)
	descIfaceTxPackets = prometheus.NewDesc(
		"rfm_interface_tx_packets_total",
		"Total packets transmitted on an interface.",
		[]string{"ifname", "family"}, nil,
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
	descErrorsTotal = prometheus.NewDesc(
		"rfm_errors_total",
		"Total errors encountered by subsystem.",
		[]string{"subsystem"}, nil,
	)

	allDescs = []*prometheus.Desc{
		descIfaceRxBytes,
		descIfaceTxBytes,
		descIfaceRxPackets,
		descIfaceTxPackets,
		descFlowBytes,
		descFlowPackets,
		descActiveFlows,
		descDroppedEvents,
		descForcedEvictions,
		descErrorsTotal,
	}
)

// MetricsCollector implements prometheus.Collector, reading BPF iface
// stats and the collector's flow table at scrape time.
type MetricsCollector struct {
	source    IfaceStatsSource
	col       *collector.Collector
	mu        sync.Mutex
	bpfMapErr uint64
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

	mc.mu.Lock()
	bpfErrs := mc.bpfMapErr
	mc.mu.Unlock()
	ch <- prometheus.MustNewConstMetric(descErrorsTotal, prometheus.CounterValue, float64(bpfErrs), "bpf_map")
}

func (mc *MetricsCollector) collectIfaceStats(ch chan<- prometheus.Metric) {
	if mc.source == nil {
		return
	}

	entries, err := mc.source.IfaceStats()
	if err != nil {
		mc.mu.Lock()
		mc.bpfMapErr++
		mc.mu.Unlock()
		log.Error("scrape iface stats", "err", err)
		return
	}

	for _, e := range entries {
		ifname := ifnameFromIndex(e.Ifindex)
		family := familyString(e.Proto)

		if e.Dir == 0 { // ingress / rx
			ch <- prometheus.MustNewConstMetric(descIfaceRxBytes, prometheus.CounterValue, float64(e.Bytes), ifname, family)
			ch <- prometheus.MustNewConstMetric(descIfaceRxPackets, prometheus.CounterValue, float64(e.Packets), ifname, family)
		} else { // egress / tx
			ch <- prometheus.MustNewConstMetric(descIfaceTxBytes, prometheus.CounterValue, float64(e.Bytes), ifname, family)
			ch <- prometheus.MustNewConstMetric(descIfaceTxPackets, prometheus.CounterValue, float64(e.Packets), ifname, family)
		}
	}
}

// flowRollupKey is the label tuple used to aggregate flows for Prometheus.
// Multiple flows with different ports but the same enrichment labels
// are summed into one series.
type flowRollupKey struct {
	ifname  string
	dir     string
	proto   string
	srcASN  string
	dstASN  string
	srcCity string
	dstCity string
}

type flowRollupValue struct {
	bytes   uint64
	packets uint64
}

func (mc *MetricsCollector) collectFlows(ch chan<- prometheus.Metric) {
	if mc.col == nil {
		return
	}

	enricher := mc.col.Enricher()
	flows := mc.col.Flows()

	// aggregate by exported label tuple to avoid duplicate series
	rollups := make(map[flowRollupKey]*flowRollupValue)

	for key, entry := range flows {
		rk := flowRollupKey{
			ifname: ifnameFromIndex(key.Ifindex),
			dir:    dirString(key.Dir),
			proto:  strconv.FormatUint(uint64(key.Proto), 10),
		}

		if enricher != nil {
			srcLabels, dstLabels := enricher.Enrich(key.SrcAddr, key.DstAddr)
			rk.srcASN = formatASN(srcLabels.ASN)
			rk.dstASN = formatASN(dstLabels.ASN)
			rk.srcCity = srcLabels.City
			rk.dstCity = dstLabels.City
		}

		rv, ok := rollups[rk]
		if !ok {
			rv = &flowRollupValue{}
			rollups[rk] = rv
		}
		rv.bytes += entry.Bytes
		rv.packets += entry.Packets
	}

	for rk, rv := range rollups {
		ch <- prometheus.MustNewConstMetric(descFlowBytes, prometheus.GaugeValue,
			float64(rv.bytes), rk.ifname, rk.dir, rk.proto, rk.srcASN, rk.dstASN, rk.srcCity, rk.dstCity)
		ch <- prometheus.MustNewConstMetric(descFlowPackets, prometheus.GaugeValue,
			float64(rv.packets), rk.ifname, rk.dir, rk.proto, rk.srcASN, rk.dstASN, rk.srcCity, rk.dstCity)
	}
}

func (mc *MetricsCollector) collectHealth(ch chan<- prometheus.Metric) {
	if mc.col == nil {
		return
	}

	stats := mc.col.Stats()
	ch <- prometheus.MustNewConstMetric(descActiveFlows, prometheus.GaugeValue, float64(stats.ActiveFlows))
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

// familyString maps BPF iface stats proto (IP version) to a label.
// BPF stores 4 for IPv4, 6 for IPv6 — not L4 protocol numbers.
func familyString(proto uint8) string {
	switch proto {
	case 4:
		return "ipv4"
	case 6:
		return "ipv6"
	default:
		return strconv.FormatUint(uint64(proto), 10)
	}
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
