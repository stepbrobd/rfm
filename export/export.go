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

	descSampleRate = prometheus.NewDesc(
		"rfm_bpf_sample_rate",
		"Packets sampled 1-in-N by the BPF programs right now.",
		nil, nil,
	)

	descFlowBytes = prometheus.NewDesc(
		"rfm_flow_bytes",
		"Estimated byte count for an active flow, scaled by the packet sample rate.",
		[]string{"ifname", "direction", "proto", "src_asn", "dst_asn", "src_city", "dst_city"}, nil,
	)
	descFlowPackets = prometheus.NewDesc(
		"rfm_flow_packets",
		"Estimated packet count for an active flow, scaled by the packet sample rate.",
		[]string{"ifname", "direction", "proto", "src_asn", "dst_asn", "src_city", "dst_city"}, nil,
	)
	descFlowSampledBytes = prometheus.NewDesc(
		"rfm_flow_sampled_bytes",
		"Observed byte count for sampled packets in an active flow.",
		[]string{"ifname", "direction", "proto", "src_asn", "dst_asn", "src_city", "dst_city"}, nil,
	)
	descFlowSampledPackets = prometheus.NewDesc(
		"rfm_flow_sampled_packets",
		"Observed packet count for sampled packets in an active flow.",
		[]string{"ifname", "direction", "proto", "src_asn", "dst_asn", "src_city", "dst_city"}, nil,
	)

	descFlowBytesTotal = prometheus.NewDesc(
		"rfm_flow_bytes_total",
		"Estimated bytes recorded per label tuple, scaled by the sample rate in force, never reset by eviction.",
		[]string{"ifname", "direction", "proto", "src_asn", "dst_asn", "src_city", "dst_city"}, nil,
	)
	descFlowPacketsTotal = prometheus.NewDesc(
		"rfm_flow_packets_total",
		"Estimated packets recorded per label tuple, scaled by the sample rate in force, never reset by eviction.",
		[]string{"ifname", "direction", "proto", "src_asn", "dst_asn", "src_city", "dst_city"}, nil,
	)
	descFlowSampledBytesTotal = prometheus.NewDesc(
		"rfm_flow_sampled_bytes_total",
		"Sampled bytes recorded per label tuple, never reset by eviction.",
		[]string{"ifname", "direction", "proto", "src_asn", "dst_asn", "src_city", "dst_city"}, nil,
	)
	descFlowSampledPacketsTotal = prometheus.NewDesc(
		"rfm_flow_sampled_packets_total",
		"Sampled packets recorded per label tuple, never reset by eviction.",
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
	descFoldedFlows = prometheus.NewDesc(
		"rfm_collector_folded_flows_total",
		"Total flows counted under empty enrichment labels because their label tuple found no room under the rollup cap.",
		nil, nil,
	)
	descErrorsTotal = prometheus.NewDesc(
		"rfm_errors_total",
		"Total errors encountered by subsystem.",
		[]string{"subsystem"}, nil,
	)

	descIPFIXConnected = prometheus.NewDesc(
		"rfm_ipfix_connected",
		"Whether a socket to the IPFIX collector is open.",
		nil, nil,
	)
	descIPFIXDials = prometheus.NewDesc(
		"rfm_ipfix_dials_total",
		"Total IPFIX socket setup attempts.",
		nil, nil,
	)
	descIPFIXDialErrors = prometheus.NewDesc(
		"rfm_ipfix_dial_errors_total",
		"Total failed IPFIX socket setups.",
		nil, nil,
	)
	descIPFIXMessages = prometheus.NewDesc(
		"rfm_ipfix_messages_total",
		"Total IPFIX messages sent.",
		nil, nil,
	)
	descIPFIXRecords = prometheus.NewDesc(
		"rfm_ipfix_records_total",
		"Total IPFIX data records sent.",
		nil, nil,
	)
	descIPFIXDropped = prometheus.NewDesc(
		"rfm_ipfix_dropped_records_total",
		"Total IPFIX records lost before they were sent, by reason.",
		[]string{"reason"}, nil,
	)
	descIPFIXSendErrors = prometheus.NewDesc(
		"rfm_ipfix_send_errors_total",
		"Total failed IPFIX sends by errno.",
		[]string{"errno"}, nil,
	)

	allDescs = []*prometheus.Desc{
		descSampleRate,
		descIfaceRxBytes,
		descIfaceTxBytes,
		descIfaceRxPackets,
		descIfaceTxPackets,
		descFlowBytes,
		descFlowPackets,
		descFlowSampledBytes,
		descFlowSampledPackets,
		descFlowBytesTotal,
		descFlowPacketsTotal,
		descFlowSampledBytesTotal,
		descFlowSampledPacketsTotal,
		descActiveFlows,
		descDroppedEvents,
		descForcedEvictions,
		descFoldedFlows,
		descErrorsTotal,
		descIPFIXConnected,
		descIPFIXDials,
		descIPFIXDialErrors,
		descIPFIXMessages,
		descIPFIXRecords,
		descIPFIXDropped,
		descIPFIXSendErrors,
	}
)

// MetricsCollector implements prometheus.Collector, reading BPF iface
// stats and the collector's flow table at scrape time
type MetricsCollector struct {
	source        IfaceStatsSource
	col           *collector.Collector
	ipfix         func() IPFIXStats
	mu            sync.Mutex
	bpfMapErr     uint64
	ifnames       map[uint32]string
	resolveIfname func(uint32) string
}

// SetIPFIX makes scrapes report the exporter counters behind stats
func (mc *MetricsCollector) SetIPFIX(stats func() IPFIXStats) {
	mc.mu.Lock()
	mc.ipfix = stats
	mc.mu.Unlock()
}

// New creates a MetricsCollector
// both source and c may be nil
func New(source IfaceStatsSource, c *collector.Collector) *MetricsCollector {
	return &MetricsCollector{
		source:        source,
		col:           c,
		ifnames:       make(map[uint32]string),
		resolveIfname: ifnameFromIndex,
	}
}

// Describe sends all metric descriptors to ch
func (mc *MetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range allDescs {
		ch <- d
	}
}

// Collect sends all current metric values to ch
func (mc *MetricsCollector) Collect(ch chan<- prometheus.Metric) {
	// interfaces come and go and an index can be reused under another
	// name, so names are resolved once per scrape rather than cached for
	// the life of the process
	mc.mu.Lock()
	clear(mc.ifnames)
	mc.mu.Unlock()

	mc.collectIfaceStats(ch)
	mc.collectFlows(ch)
	mc.collectRollups(ch)
	if mc.source != nil {
		ch <- prometheus.MustNewConstMetric(descSampleRate, prometheus.GaugeValue, float64(mc.sampleRate()))
	}

	mc.mu.Lock()
	bpfErrs := mc.bpfMapErr
	ipfix := mc.ipfix
	mc.mu.Unlock()

	// the ipfix subsystem error counter is every loss the exporter counted,
	// the collector's own tally of refused records repeats the exporter's
	// queue drops and only stands in when no exporter stats are wired
	var ipfixErrs uint64
	haveIPFIX := ipfix != nil
	if haveIPFIX {
		s := ipfix()
		ipfixErrs = s.Failures()
		var connected float64
		if s.Connected {
			connected = 1
		}
		ch <- prometheus.MustNewConstMetric(descIPFIXConnected, prometheus.GaugeValue, connected)
		ch <- prometheus.MustNewConstMetric(descIPFIXDials, prometheus.CounterValue, float64(s.Dials))
		ch <- prometheus.MustNewConstMetric(descIPFIXDialErrors, prometheus.CounterValue, float64(s.DialErrors))
		ch <- prometheus.MustNewConstMetric(descIPFIXMessages, prometheus.CounterValue, float64(s.Messages))
		ch <- prometheus.MustNewConstMetric(descIPFIXRecords, prometheus.CounterValue, float64(s.Records))
		ch <- prometheus.MustNewConstMetric(descIPFIXDropped, prometheus.CounterValue, float64(s.QueueDropped), "queue_full")
		ch <- prometheus.MustNewConstMetric(descIPFIXDropped, prometheus.CounterValue, float64(s.Unsent), "unconnected")
		ch <- prometheus.MustNewConstMetric(descIPFIXDropped, prometheus.CounterValue, float64(s.EncodeErrors), "encode")
		for errno, n := range s.SendErrors {
			ch <- prometheus.MustNewConstMetric(descIPFIXSendErrors, prometheus.CounterValue, float64(n), errno)
		}
	}

	if mc.col != nil {
		// single Stats() call for a consistent snapshot
		stats := mc.col.Stats()
		ch <- prometheus.MustNewConstMetric(descActiveFlows, prometheus.GaugeValue, float64(stats.ActiveFlows))
		ch <- prometheus.MustNewConstMetric(descDroppedEvents, prometheus.CounterValue, float64(stats.DroppedEvents))
		ch <- prometheus.MustNewConstMetric(descForcedEvictions, prometheus.CounterValue, float64(stats.ForcedEvictions))
		ch <- prometheus.MustNewConstMetric(descFoldedFlows, prometheus.CounterValue, float64(stats.FoldedFlows))
		bpfErrs += stats.BPFMapErrors
		ch <- prometheus.MustNewConstMetric(descErrorsTotal, prometheus.CounterValue, float64(stats.RingBufErrors), "ring_buffer")
		if !haveIPFIX {
			ipfixErrs = stats.IPFIXErrors
		}
		ch <- prometheus.MustNewConstMetric(descErrorsTotal, prometheus.CounterValue, float64(ipfixErrs), "ipfix")
	}
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
		ifname := mc.ifname(e.Ifindex)
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

// flowRollupKey is the label tuple used to aggregate flows for Prometheus
// multiple flows with different ports but the same enrichment labels
// are summed into one series
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
	sampledBytes   uint64
	sampledPackets uint64
	estBytes       uint64
	estPackets     uint64
}

func (mc *MetricsCollector) collectFlows(ch chan<- prometheus.Metric) {
	if mc.col == nil {
		return
	}

	flows := mc.col.Flows()

	// aggregate by exported label tuple to avoid duplicate series, the
	// labels were resolved when each flow was created
	rollups := make(map[flowRollupKey]*flowRollupValue)

	for key, entry := range flows {
		rk := mc.rollupKey(key.Ifindex, key.Dir, key.Proto, entry.Src, entry.Dst)

		rv, ok := rollups[rk]
		if !ok {
			rv = &flowRollupValue{}
			rollups[rk] = rv
		}
		rv.sampledBytes += entry.Bytes
		rv.sampledPackets += entry.Packets
		rv.estBytes += entry.EstBytes
		rv.estPackets += entry.EstPackets
	}

	// the estimates were scaled when each event was recorded, with the
	// sample rate in force at that moment
	for rk, rv := range rollups {
		ch <- prometheus.MustNewConstMetric(descFlowBytes, prometheus.GaugeValue,
			float64(rv.estBytes),
			rk.ifname, rk.dir, rk.proto, rk.srcASN, rk.dstASN, rk.srcCity, rk.dstCity)
		ch <- prometheus.MustNewConstMetric(descFlowPackets, prometheus.GaugeValue,
			float64(rv.estPackets),
			rk.ifname, rk.dir, rk.proto, rk.srcASN, rk.dstASN, rk.srcCity, rk.dstCity)
		ch <- prometheus.MustNewConstMetric(descFlowSampledBytes, prometheus.GaugeValue,
			float64(rv.sampledBytes),
			rk.ifname, rk.dir, rk.proto, rk.srcASN, rk.dstASN, rk.srcCity, rk.dstCity)
		ch <- prometheus.MustNewConstMetric(descFlowSampledPackets, prometheus.GaugeValue,
			float64(rv.sampledPackets),
			rk.ifname, rk.dir, rk.proto, rk.srcASN, rk.dstASN, rk.srcCity, rk.dstCity)
	}
}

func (mc *MetricsCollector) rollupKey(ifindex uint32, dir, proto uint8, src, dst collector.Labels) flowRollupKey {
	return flowRollupKey{
		ifname:  mc.ifname(ifindex),
		dir:     dirString(dir),
		proto:   strconv.FormatUint(uint64(proto), 10),
		srcASN:  formatASN(src.ASN),
		dstASN:  formatASN(dst.ASN),
		srcCity: src.City,
		dstCity: dst.City,
	}
}

// collectRollups emits the monotonic per label counters, a new tuple shows
// up at zero first
func (mc *MetricsCollector) collectRollups(ch chan<- prometheus.Metric) {
	if mc.col == nil {
		return
	}

	for _, r := range mc.col.ScrapeRollups(nil) {
		key := r.Key
		rk := mc.rollupKey(key.Ifindex, key.Dir, key.Proto, key.Src, key.Dst)
		ch <- prometheus.MustNewConstMetric(descFlowBytesTotal, prometheus.CounterValue,
			float64(r.EstBytes),
			rk.ifname, rk.dir, rk.proto, rk.srcASN, rk.dstASN, rk.srcCity, rk.dstCity)
		ch <- prometheus.MustNewConstMetric(descFlowPacketsTotal, prometheus.CounterValue,
			float64(r.EstPackets),
			rk.ifname, rk.dir, rk.proto, rk.srcASN, rk.dstASN, rk.srcCity, rk.dstCity)
		ch <- prometheus.MustNewConstMetric(descFlowSampledBytesTotal, prometheus.CounterValue,
			float64(r.Bytes),
			rk.ifname, rk.dir, rk.proto, rk.srcASN, rk.dstASN, rk.srcCity, rk.dstCity)
		ch <- prometheus.MustNewConstMetric(descFlowSampledPacketsTotal, prometheus.CounterValue,
			float64(r.Packets),
			rk.ifname, rk.dir, rk.proto, rk.srcASN, rk.dstASN, rk.srcCity, rk.dstCity)
	}
}

func (mc *MetricsCollector) sampleRate() uint32 {
	src, ok := mc.source.(SampleRateSource)
	if !ok {
		return 1
	}

	rate, err := src.SampleRate()
	if err != nil {
		mc.mu.Lock()
		mc.bpfMapErr++
		mc.mu.Unlock()
		log.Error("scrape sample rate", "err", err)
		return 1
	}
	if rate == 0 {
		return 1
	}
	return rate
}

func (mc *MetricsCollector) ifname(ifindex uint32) string {
	mc.mu.Lock()
	if name, ok := mc.ifnames[ifindex]; ok {
		mc.mu.Unlock()
		return name
	}
	mc.mu.Unlock()

	name := mc.resolveIfname(ifindex)

	mc.mu.Lock()
	if cached, ok := mc.ifnames[ifindex]; ok {
		mc.mu.Unlock()
		return cached
	}
	mc.ifnames[ifindex] = name
	mc.mu.Unlock()

	return name
}

// ifnameFromIndex resolves an interface index to a name, falling back
// to the string representation of the index
func ifnameFromIndex(ifindex uint32) string {
	iface, err := net.InterfaceByIndex(int(ifindex))
	if err != nil {
		return fmt.Sprintf("%d", ifindex)
	}
	return iface.Name
}

// familyString maps BPF iface stats proto (IP version) to a label
// BPF stores 4 for IPv4 and 6 for IPv6, not L4 protocol numbers
func familyString(proto uint8) string {
	switch proto {
	case 4:
		return "ipv4"
	case 6:
		return "ipv6"
	default:
		return "other"
	}
}

// dirString returns the human-readable direction label
func dirString(dir uint8) string {
	if dir == 0 {
		return "ingress"
	}
	return "egress"
}

// formatASN formats an ASN as a string, returning empty string for zero
func formatASN(asn uint32) string {
	if asn == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(asn), 10)
}
