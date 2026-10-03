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
		"Sample rate N of the BPF programs right now, one skb in N becomes a flow event.",
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
		"Total IPFIX records lost, by reason.",
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
// stats and the collector's label tuples at scrape time
type MetricsCollector struct {
	source        IfaceStatsSource
	col           *collector.Collector
	ipfix         func() IPFIXStats
	mu            sync.Mutex
	bpfMapErr     uint64
	ifnames       map[uint32]string
	resolveIfname func(uint32) string
	// ifaceErrs and gsoErrs are the last counts of refused interface counter
	// updates and of unparsed gso skbs read from the source, errorSources the
	// subsystems wired from outside
	ifaceErrs    uint64
	gsoErrs      uint64
	errorSources []errorSource

	// rollupMu serializes the flow series part of overlapping scrapes, it
	// guards the sample buffer and the label cache
	rollupMu sync.Mutex
	samples  []collector.RollupSample
	labels   map[uint64]*tupleLabels
	gen      uint64
}

// SetIPFIX makes scrapes report the exporter counters behind stats
func (mc *MetricsCollector) SetIPFIX(stats func() IPFIXStats) {
	mc.mu.Lock()
	mc.ipfix = stats
	mc.mu.Unlock()
}

// errorSource is one count of errors of a subsystem
type errorSource struct {
	subsystem string
	count     func() uint64
}

// AddErrors makes scrapes add count to rfm_errors_total{subsystem}, count
// must never go back, sources of one subsystem add up
func (mc *MetricsCollector) AddErrors(subsystem string, count func() uint64) {
	mc.mu.Lock()
	mc.errorSources = append(mc.errorSources, errorSource{subsystem, count})
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
	mc.collectRollups(ch)
	if mc.source != nil {
		ch <- prometheus.MustNewConstMetric(descSampleRate, prometheus.GaugeValue, float64(mc.sampleRate()))
	}

	ifaceErrs := mc.ifaceStatsErrors()
	gsoErrs, countsGSO := mc.gsoHeaderErrors()

	mc.mu.Lock()
	bpfErrs := mc.bpfMapErr + ifaceErrs
	ipfix := mc.ipfix
	sources := mc.errorSources
	mc.mu.Unlock()

	// the ipfix subsystem error counter is every record the exporter lost,
	// the sum of the dropped records over their reasons, and 0 without one
	var ipfixErrs uint64
	if ipfix != nil {
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
		ch <- prometheus.MustNewConstMetric(descIPFIXDropped, prometheus.CounterValue, float64(s.SendFailed), "send")
		for errno, n := range s.SendErrors {
			ch <- prometheus.MustNewConstMetric(descIPFIXSendErrors, prometheus.CounterValue, float64(n), errno)
		}
	}

	errs := map[string]uint64{"bpf_map": bpfErrs}
	if countsGSO {
		errs["gso_header"] = gsoErrs
	}
	if mc.col != nil {
		// single Stats() call for a consistent snapshot
		stats := mc.col.Stats()
		ch <- prometheus.MustNewConstMetric(descActiveFlows, prometheus.GaugeValue, float64(stats.ActiveFlows))
		ch <- prometheus.MustNewConstMetric(descDroppedEvents, prometheus.CounterValue, float64(stats.DroppedEvents))
		ch <- prometheus.MustNewConstMetric(descForcedEvictions, prometheus.CounterValue, float64(stats.ForcedEvictions))
		ch <- prometheus.MustNewConstMetric(descFoldedFlows, prometheus.CounterValue, float64(stats.FoldedFlows))
		errs["bpf_map"] += stats.BPFMapErrors
		errs["ring_buffer"] = stats.RingBufErrors
		errs["ipfix"] = ipfixErrs
	}
	for _, s := range sources {
		errs[s.subsystem] += s.count()
	}
	for subsystem, n := range errs {
		ch <- prometheus.MustNewConstMetric(descErrorsTotal, prometheus.CounterValue, float64(n), subsystem)
	}
}

// ifaceStatsErrors returns how many counter updates the interface stats map
// refused
func (mc *MetricsCollector) ifaceStatsErrors() uint64 {
	src, ok := mc.source.(IfaceStatsErrorSource)
	if !ok {
		return 0
	}
	return mc.probeErrors("iface stats errors", src.IfaceStatsErrors, &mc.ifaceErrs)
}

// gsoHeaderErrors returns how many gso skbs the programs counted without
// parsing their headers, and false for a source that does not count them
func (mc *MetricsCollector) gsoHeaderErrors() (uint64, bool) {
	src, ok := mc.source.(GSOHeaderErrorSource)
	if !ok {
		return 0, false
	}
	return mc.probeErrors("gso header errors", src.GSOHeaderErrors, &mc.gsoErrs), true
}

// probeErrors returns the count of errors read reports and keeps it in last,
// a failed read counts as a bpf_map error and returns last instead, so
// neither count goes back
func (mc *MetricsCollector) probeErrors(what string, read func() (uint64, error), last *uint64) uint64 {
	n, err := read()

	mc.mu.Lock()
	defer mc.mu.Unlock()
	if err != nil {
		mc.bpfMapErr++
		log.Error("scrape "+what, "err", err)
		return *last
	}
	*last = n
	return n
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

	// deleting the key under a hash map iterator restarts the walk, so a
	// scrape that overlaps a detach can read a key twice, and the registry
	// fails the whole scrape over a repeated series, the later read wins
	type statKey struct {
		ifindex    uint32
		dir, proto uint8
	}
	last := make(map[statKey]int, len(entries))
	for i, e := range entries {
		last[statKey{e.Ifindex, e.Dir, e.Proto}] = i
	}

	for i, e := range entries {
		if last[statKey{e.Ifindex, e.Dir, e.Proto}] != i {
			continue
		}
		ifname := validLabel(mc.ifname(e.Ifindex))
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
