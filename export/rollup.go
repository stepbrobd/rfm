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

// tupleLabels are the label pairs of one tuple, rebuilt when its interface name changes
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
		collector.Direction(k.Dir),
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

// counterMetric writes cached labels and a preallocated value
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

// collectRollups emits the counters of every tuple
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

	counters := make([]counterMetric, 4*len(mc.samples))
	counter := func(m *counterMetric, desc *prometheus.Desc, labels []*dto.LabelPair, v uint64) {
		m.desc, m.labels, m.value = desc, labels, float64(v)
		m.out.Value = &m.value
	}
	for i := range mc.samples {
		s := &mc.samples[i]
		labels := mc.tupleLabels(s)
		c := counters[4*i : 4*i+4]
		counter(&c[0], descFlowBytesTotal, labels, s.EstBytes)
		counter(&c[1], descFlowPacketsTotal, labels, s.EstPackets)
		counter(&c[2], descFlowSampledBytesTotal, labels, s.Bytes)
		counter(&c[3], descFlowSampledPacketsTotal, labels, s.Packets)
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
