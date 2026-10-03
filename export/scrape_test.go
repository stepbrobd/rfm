package export

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"ysun.co/rfm/collector"
)

// tupleEnricher gives every source address a label tuple of its own
type tupleEnricher struct{}

func (tupleEnricher) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	b := src.As16()
	i := uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])
	return collector.Labels{ASN: 64512 + i, City: "src-" + strconv.Itoa(int(i%97))},
		collector.Labels{ASN: 13335, City: "dst"}
}

func tupleEvent(tuple, port int) collector.FlowEvent {
	return collector.FlowEvent{
		Ifindex: 2, Dir: 0, Proto: 6,
		SrcAddr: netip.AddrFrom4([4]byte{10, byte(tuple >> 16), byte(tuple >> 8), byte(tuple)}),
		DstAddr: netip.MustParseAddr("192.0.2.1"),
		SrcPort: uint16(port), DstPort: 443,
		Segs: 1, Len: 1500, L2Len: 14,
	}
}

// fleetCollector holds the shape of the busiest fleet node, 10000 label
// tuples of which 2675 carry 50000 live flows, about 50700 flow series
func fleetCollector(tb testing.TB) *collector.Collector {
	tb.Helper()
	c := collector.New(30*time.Second, tupleEnricher{}, 0)
	c.SetSampleRate(10, 0)

	t0 := time.Now()
	for i := range 10_000 {
		c.Record(tupleEvent(i, 1), t0)
	}
	c.Evict(t0.Add(time.Minute))
	for j := range 50_000 {
		c.Record(tupleEvent(j%2675, 2+j/2675), t0.Add(time.Minute))
	}
	return c
}

// discardWriter takes the response like a socket would, without keeping the
// body around, so a benchmark measures the scrape and not a growing buffer
type discardWriter struct {
	header http.Header
	code   int
	n      int
}

func (w *discardWriter) Header() http.Header         { return w.header }
func (w *discardWriter) WriteHeader(code int)        { w.code = code }
func (w *discardWriter) Write(b []byte) (int, error) { w.n += len(b); return len(b), nil }

func scrapeOnce(tb testing.TB, h http.Handler) {
	tb.Helper()
	w := &discardWriter{header: http.Header{}, code: http.StatusOK}
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.code != http.StatusOK || w.n == 0 {
		tb.Fatalf("scrape status = %d after %d bytes", w.code, w.n)
	}
}

// smallFleetCollector is fleetCollector at a tenth of the size
func smallFleetCollector(tb testing.TB) *collector.Collector {
	tb.Helper()
	c := collector.New(30*time.Second, tupleEnricher{}, 0)
	c.SetSampleRate(10, 0)

	t0 := time.Now()
	for i := range 1000 {
		c.Record(tupleEvent(i, 1), t0)
	}
	c.Evict(t0.Add(time.Minute))
	for j := range 5000 {
		c.Record(tupleEvent(j%268, 2+j/268), t0.Add(time.Minute))
	}
	return c
}

// drainCollect runs one Collect and returns the metrics it sent
func drainCollect(mc *MetricsCollector) []prometheus.Metric {
	ch := make(chan prometheus.Metric, 1024)
	done := make(chan []prometheus.Metric)
	go func() {
		var out []prometheus.Metric
		for m := range ch {
			out = append(out, m)
		}
		done <- out
	}()
	mc.Collect(ch)
	close(ch)
	return <-done
}

func TestScrapeDoesNotRebuildEverySeries(t *testing.T) {
	mc := New(nil, smallFleetCollector(t))
	// a real lookup dumps every link of the host, which allocates by the
	// number of interfaces
	mc.resolveIfname = func(uint32) string { return "eth0" }
	series := len(drainCollect(mc))
	if series < 5000 {
		t.Fatalf("series = %d, want the about 5000 of the shape", series)
	}

	// a scrape walks the label tuples, it neither copies the flow table nor
	// builds the labels of every series again
	ch := make(chan prometheus.Metric, series+64)
	allocs := testing.AllocsPerRun(5, func() {
		mc.Collect(ch)
		for len(ch) > 0 {
			<-ch
		}
	})
	if allocs > float64(series)/10 {
		t.Fatalf("one scrape of %d series allocates %v times, want under one allocation per ten series", series, allocs)
	}
}

func TestScrapeSeriesMatchFlowsAndRollups(t *testing.T) {
	c := smallFleetCollector(t)
	// a second interface and direction join the mix
	other := tupleEvent(7, 9)
	other.Ifindex, other.Dir = 3, 1
	c.Record(other, time.Now())

	mc := New(nil, c)
	mc.resolveIfname = func(ifindex uint32) string { return "if" + strconv.Itoa(int(ifindex)) }
	drainCollect(mc)

	type id struct {
		name   string
		labels string
	}
	got := map[id]float64{}
	for _, m := range drainCollect(mc) {
		name := extractName(m.Desc())
		if !strings.HasPrefix(name, "rfm_flow_") {
			continue
		}
		labels := metricLabels(t, m)
		got[id{name, labelString(labels)}] += metricValue(t, m)
	}

	want := map[id]float64{}
	keyOf := func(ifindex uint32, dir, proto uint8, src, dst collector.Labels) string {
		return labelString(map[string]string{
			"ifname": "if" + strconv.Itoa(int(ifindex)), "direction": dirString(dir), "proto": strconv.Itoa(int(proto)),
			"src_asn": formatASN(src.ASN), "dst_asn": formatASN(dst.ASN), "src_city": src.City, "dst_city": dst.City,
		})
	}
	for k, e := range c.Flows() {
		l := keyOf(k.Ifindex, k.Dir, k.Proto, e.Src, e.Dst)
		want[id{"rfm_flow_bytes", l}] += float64(e.EstBytes)
		want[id{"rfm_flow_packets", l}] += float64(e.EstPackets)
		want[id{"rfm_flow_sampled_bytes", l}] += float64(e.Bytes)
		want[id{"rfm_flow_sampled_packets", l}] += float64(e.Packets)
	}
	// both scrapes above showed every tuple, one more shows all they counted
	for _, r := range c.ScrapeRollups(nil) {
		l := keyOf(r.Key.Ifindex, r.Key.Dir, r.Key.Proto, r.Key.Src, r.Key.Dst)
		want[id{"rfm_flow_bytes_total", l}] = float64(r.EstBytes)
		want[id{"rfm_flow_packets_total", l}] = float64(r.EstPackets)
		want[id{"rfm_flow_sampled_bytes_total", l}] = float64(r.Bytes)
		want[id{"rfm_flow_sampled_packets_total", l}] = float64(r.Packets)
	}
	if len(got) != len(want) {
		t.Fatalf("series = %d, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s{%s} = %v, want %v", k.name, k.labels, got[k], v)
		}
	}
}

func TestScrapeFollowsInterfaceRenames(t *testing.T) {
	c := collector.New(time.Minute, tupleEnricher{}, 0)
	c.Record(tupleEvent(1, 1), time.Now())
	mc := New(nil, c)

	name := "eth0"
	mc.resolveIfname = func(uint32) string { return name }
	ifnames := func() map[string]bool {
		seen := map[string]bool{}
		for _, m := range drainCollect(mc) {
			if strings.HasPrefix(extractName(m.Desc()), "rfm_flow_") {
				seen[metricLabels(t, m)["ifname"]] = true
			}
		}
		return seen
	}
	if got := ifnames(); len(got) != 1 || !got["eth0"] {
		t.Fatalf("ifnames = %v, want eth0", got)
	}
	name = "wan0"
	if got := ifnames(); len(got) != 1 || !got["wan0"] {
		t.Fatalf("ifnames after the rename = %v, want wan0", got)
	}
}

func TestFlowLabelNamesMatchEveryFlowFamily(t *testing.T) {
	// the registry copies and sorts the labels of every series whose pairs
	// come unsorted
	if !slices.IsSorted(flowLabelNames[:]) {
		t.Fatalf("flow label names %v are not sorted", flowLabelNames)
	}
	for _, d := range []*prometheus.Desc{
		descFlowBytes, descFlowPackets, descFlowSampledBytes, descFlowSampledPackets,
		descFlowBytesTotal, descFlowPacketsTotal, descFlowSampledBytesTotal, descFlowSampledPacketsTotal,
	} {
		var out dto.Metric
		if err := prometheus.MustNewConstMetric(d, prometheus.CounterValue, 0, make([]string, len(flowLabelNames))...).Write(&out); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, l := range out.GetLabel() {
			names = append(names, l.GetName())
		}
		if !slices.Equal(names, flowLabelNames[:]) {
			t.Fatalf("%s has labels %v, want the cached %v", d, names, flowLabelNames)
		}
	}
}

func TestScrapeSurvivesLabelsThatAreNotUTF8(t *testing.T) {
	c := collector.New(time.Minute, &staticEnricher{srcCity: "M\xfcnchen"}, 0)
	c.Record(tupleEvent(1, 1), time.Now())
	reg := prometheus.NewRegistry()
	reg.MustRegister(New(nil, c))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "rfm_flow_bytes_total" {
			continue
		}
		for _, l := range mf.GetMetric()[0].GetLabel() {
			if l.GetName() == "src_city" && l.GetValue() != "M\uFFFDnchen" {
				t.Fatalf("src_city = %q, want the invalid byte replaced", l.GetValue())
			}
		}
		return
	}
	t.Fatal("rfm_flow_bytes_total missing")
}

// labelString renders labels in a fixed order
func labelString(labels map[string]string) string {
	var b strings.Builder
	for _, k := range []string{"ifname", "direction", "proto", "src_asn", "dst_asn", "src_city", "dst_city"} {
		b.WriteString(k + "=" + labels[k] + ",")
	}
	return b.String()
}

func BenchmarkScrapeFleetShape(b *testing.B) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(New(nil, fleetCollector(b)))
	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})

	// the first scrape shows new tuples at zero, measure the steady state
	scrapeOnce(b, h)
	scrapeOnce(b, h)

	b.ReportAllocs()
	for b.Loop() {
		scrapeOnce(b, h)
	}
}
