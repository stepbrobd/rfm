package export

import (
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"ysun.co/rfm/collector"
)

// flowLabelNames are the label names of every flow series sorted by name,
// the order the registry expects label pairs in
var flowLabelNames = [7]string{"direction", "dst_asn", "dst_city", "ifname", "proto", "src_asn", "src_city"}

// tupleLabels are the label pairs of one rollup tuple, built once and shared
// by the series of the tuple in every scrape, the labels of a tuple never
// change except the name of its interface, which every scrape checks
// one allocation holds the values, the pairs and the slice of them
type tupleLabels struct {
	ifname string
	// gen is the last scrape that saw the tuple, a tuple that left the
	// collector leaves the cache with the next scrape
	gen    uint64
	values [len(flowLabelNames)]string
	pairs  [len(flowLabelNames)]dto.LabelPair
	ptrs   [len(flowLabelNames)]*dto.LabelPair
}

func newTupleLabels(ifname string, k collector.RollupKey) *tupleLabels {
	l := &tupleLabels{ifname: ifname}
	l.values = [len(flowLabelNames)]string{
		dirString(k.Dir),
		formatASN(k.Dst.ASN),
		validLabel(k.Dst.City),
		validLabel(ifname),
		strconv.FormatUint(uint64(k.Proto), 10),
		formatASN(k.Src.ASN),
		validLabel(k.Src.City),
	}
	for i := range l.pairs {
		l.pairs[i].Name = &flowLabelNames[i]
		l.pairs[i].Value = &l.values[i]
		l.ptrs[i] = &l.pairs[i]
	}
	return l
}

// counterMetric and gaugeMetric are one series of a rollup tuple in one
// scrape, they carry the protobuf value the registry takes so writing them
// allocates nothing, and they share the cached label pairs, which no reader
// modifies
type counterMetric struct {
	desc   *prometheus.Desc
	labels []*dto.LabelPair
	value  float64
	out    dto.Counter
}

func (m *counterMetric) Desc() *prometheus.Desc {
	return m.desc
}

func (m *counterMetric) Write(out *dto.Metric) error {
	out.Label = m.labels
	out.Counter = &m.out
	return nil
}

type gaugeMetric struct {
	desc   *prometheus.Desc
	labels []*dto.LabelPair
	value  float64
	out    dto.Gauge
}

func (m *gaugeMetric) Desc() *prometheus.Desc {
	return m.desc
}

func (m *gaugeMetric) Write(out *dto.Metric) error {
	out.Label = m.labels
	out.Gauge = &m.out
	return nil
}

// collectRollups emits the flow gauges and counters of every label tuple
// the gauges sum the live flows of a tuple and are left out while it has
// none, the counters of a new tuple start at zero, see ScrapeRollups
// the series of one scrape come from two allocations and take their labels
// from the cache, so a scrape neither copies the flow table nor builds the
// labels of every series again
func (mc *MetricsCollector) collectRollups(ch chan<- prometheus.Metric) {
	if mc.col == nil {
		return
	}

	mc.rollupMu.Lock()
	defer mc.rollupMu.Unlock()

	mc.samples = mc.col.ScrapeRollups(mc.samples[:0])
	mc.gen++
	if mc.labels == nil {
		mc.labels = make(map[uint64]*tupleLabels)
	}

	live := 0
	for i := range mc.samples {
		if mc.samples[i].Flows > 0 {
			live++
		}
	}
	counters := make([]counterMetric, 4*len(mc.samples))
	gauges := make([]gaugeMetric, 4*live)
	counter := func(m *counterMetric, desc *prometheus.Desc, labels []*dto.LabelPair, v uint64) {
		m.desc, m.labels, m.value = desc, labels, float64(v)
		m.out.Value = &m.value
	}
	gauge := func(m *gaugeMetric, desc *prometheus.Desc, labels []*dto.LabelPair, v uint64) {
		m.desc, m.labels, m.value = desc, labels, float64(v)
		m.out.Value = &m.value
	}
	g := 0
	for i := range mc.samples {
		s := &mc.samples[i]
		labels := mc.tupleLabels(s)
		// the estimates were scaled when each event was recorded, with the
		// sample rate in force at that moment
		if s.Flows > 0 {
			gauge(&gauges[g], descFlowBytes, labels, s.Live.EstBytes)
			gauge(&gauges[g+1], descFlowPackets, labels, s.Live.EstPackets)
			gauge(&gauges[g+2], descFlowSampledBytes, labels, s.Live.Bytes)
			gauge(&gauges[g+3], descFlowSampledPackets, labels, s.Live.Packets)
			g += 4
		}
		c := counters[4*i : 4*i+4]
		counter(&c[0], descFlowBytesTotal, labels, s.EstBytes)
		counter(&c[1], descFlowPacketsTotal, labels, s.EstPackets)
		counter(&c[2], descFlowSampledBytesTotal, labels, s.Bytes)
		counter(&c[3], descFlowSampledPacketsTotal, labels, s.Packets)
	}
	for i := range gauges {
		ch <- &gauges[i]
	}
	for i := range counters {
		ch <- &counters[i]
	}

	for id, l := range mc.labels {
		if l.gen != mc.gen {
			delete(mc.labels, id)
		}
	}
	// a buffer that grew for a burst of tuples goes once it is mostly unused
	if cap(mc.samples) > 4096 && len(mc.samples) < cap(mc.samples)/4 {
		mc.samples = nil
	}
}

// tupleLabels returns the cached label pairs of s, built again when the
// name of its interface changed
// it must be called with rollupMu held
func (mc *MetricsCollector) tupleLabels(s *collector.RollupSample) []*dto.LabelPair {
	ifname := mc.ifname(s.Key.Ifindex)
	l := mc.labels[s.ID]
	if l == nil || l.ifname != ifname {
		l = newTupleLabels(ifname, s.Key)
		mc.labels[s.ID] = l
	}
	l.gen = mc.gen
	return l.ptrs[:]
}

// validLabel replaces bytes that are not utf-8, which the registry would
// refuse together with the whole scrape
func validLabel(v string) string {
	return strings.ToValidUTF8(v, "\uFFFD")
}
