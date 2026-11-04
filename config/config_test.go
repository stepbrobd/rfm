package config

import (
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// base is the smallest config Parse accepts
const base = `[agent]
interfaces = ["eth0"]
`

func TestParse(t *testing.T) {
	defaults := Config{Agent: AgentConfig{
		Interfaces: []string{"eth0"},
		BPF:        BPFConfig{SampleRate: 100, RingBufSize: 65536, WakeupBatch: 256, MaxSampleRate: 1000},
		Collector:  CollectorConfig{MaxFlows: 65536, EvictionTimeout: 30 * time.Second, ActiveTimeout: time.Minute},
		// the queue holds a sweep of a full table
		IPFIX:      IPFIXConfig{TemplateRefresh: time.Minute, ObservationDomainID: 1, QueueSize: 65536, MaxMessageSize: 1200},
		Prometheus: PrometheusConfig{Host: "::1", Port: 9669},
	}}
	with := func(change func(*AgentConfig)) Config {
		cfg := defaults
		change(&cfg.Agent)
		return cfg
	}

	for _, tc := range []struct {
		name string
		data string
		want Config
	}{
		{"defaults", base, defaults},
		{"every key", `
[agent]
interfaces = ["eth0", "tailscale0"]

[agent.bpf]
sample_rate = 50
ring_buf_size = 131072
wakeup_batch = 256
iface_stats_size = 8192
iface_slots = 4
adaptive_sampling = true
max_sample_rate = 640
pin_path = "/sys/fs/bpf/rfm"
sampled_only = true

[agent.collector]
max_flows = 1024
eviction_timeout = "10s"
active_timeout = "2m"

[agent.ipfix]
host = "192.0.2.10"
port = 2055
template_refresh = "30s"
observation_domain_id = 42
max_message_size = 512

[agent.ipfix.bind]
host = "192.0.2.20"
port = 40000

[agent.prometheus]
host = "127.0.0.1"
port = 8080

[agent.enrich.mmdb]
asn_db = "/tmp/asn.mmdb"
city_db = "/tmp/city.mmdb"

[agent.enrich.rib.bmp]
host = "127.0.0.1"
port = 11020

[agent.control]
socket = "/run/rfm/rfm.sock"
`, Config{Agent: AgentConfig{
			Interfaces: []string{"eth0", "tailscale0"},
			BPF:        BPFConfig{SampleRate: 50, RingBufSize: 131072, WakeupBatch: 256, IfaceStatsSize: 8192, IfaceSlots: 4, AdaptiveSampling: true, MaxSampleRate: 640, PinPath: "/sys/fs/bpf/rfm", SampledOnly: true},
			Collector:  CollectorConfig{MaxFlows: 1024, EvictionTimeout: 10 * time.Second, ActiveTimeout: 2 * time.Minute},
			// a small table keeps the queue at its floor
			IPFIX:      IPFIXConfig{Host: "192.0.2.10", Port: 2055, Bind: IPFIXBindConfig{Host: "192.0.2.20", Port: 40000}, TemplateRefresh: 30 * time.Second, ObservationDomainID: 42, QueueSize: DefaultIPFIXQueueSize, MaxMessageSize: 512},
			Prometheus: PrometheusConfig{Host: "127.0.0.1", Port: 8080},
			Enrich:     EnrichConfig{MMDB: MMDBConfig{ASNDB: "/tmp/asn.mmdb", CityDB: "/tmp/city.mmdb"}, RIB: RIBConfig{BMP: BMPConfig{Host: "127.0.0.1", Port: 11020}}},
			Control:    ControlConfig{Socket: "/run/rfm/rfm.sock"},
		}}},
		{"bmp port alone", base + "[agent.enrich.rib.bmp]\nport = 11020\n", with(func(a *AgentConfig) { a.Enrich.RIB.BMP = BMPConfig{Host: "::1", Port: 11020} })},
		{"bmp host alone", base + "[agent.enrich.rib.bmp]\nhost = \"127.0.0.1\"\n", with(func(a *AgentConfig) { a.Enrich.RIB.BMP = BMPConfig{Host: "127.0.0.1", Port: 11019} })},
		{"ipfix port alone", base + "[agent.ipfix]\nport = 2055\n", with(func(a *AgentConfig) { a.IPFIX.Host, a.IPFIX.Port = "::1", 2055 })},
		{"ipfix host alone", base + "[agent.ipfix]\nhost = \"127.0.0.1\"\n", with(func(a *AgentConfig) { a.IPFIX.Host, a.IPFIX.Port = "127.0.0.1", 4739 })},
		// the ring and the wakeup batch follow the sample rate unless set
		{"rate 1 rings", base + "[agent.bpf]\nsample_rate = 1\n", with(func(a *AgentConfig) { a.BPF.SampleRate, a.BPF.RingBufSize, a.BPF.WakeupBatch = 1, 262144, 1024 })},
		{"rate 10 rings", base + "[agent.bpf]\nsample_rate = 10\n", with(func(a *AgentConfig) { a.BPF.SampleRate, a.BPF.RingBufSize, a.BPF.WakeupBatch = 10, 65536, 256 })},
		{"set ring, derived batch", base + "[agent.bpf]\nring_buf_size = 65536\n", with(func(a *AgentConfig) { a.BPF.RingBufSize, a.BPF.WakeupBatch = 65536, 256 })},
		{"set batch, ring for it", base + "[agent.bpf]\nwakeup_batch = 1024\n", with(func(a *AgentConfig) { a.BPF.RingBufSize, a.BPF.WakeupBatch = 131072, 1024 })},
		{"set batch, rate ring holds it", base + "[agent.bpf]\nsample_rate = 1\nwakeup_batch = 129\n", with(func(a *AgentConfig) { a.BPF.SampleRate, a.BPF.RingBufSize, a.BPF.WakeupBatch = 1, 262144, 129 })},
		{"active timeout off", base + "[agent.collector]\nactive_timeout = \"0s\"\n", with(func(a *AgentConfig) { a.Collector.ActiveTimeout = 0 })},
		// a message holds one record and the template of its family
		{"smallest message", base + "[agent.ipfix]\nmax_message_size = " + strconv.Itoa(MinIPFIXMaxMessageSize) + "\n", with(func(a *AgentConfig) { a.IPFIX.MaxMessageSize = MinIPFIXMaxMessageSize })},
	} {
		got, err := Parse([]byte(tc.data))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !reflect.DeepEqual(*got, tc.want) {
			t.Fatalf("%s: config = %+v, want %+v", tc.name, *got, tc.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	// a power of two below the page size passes the power of two check but
	// the kernel would still refuse it
	halfPage := strconv.Itoa(os.Getpagesize() / 2)

	for _, tc := range []struct{ data, err string }{
		{"[agent]\n[agent.bpf]\nsample_rate = 100\n", "agent.interfaces must be non-empty"},
		{"[agent]\ninterfaces = []\n", "agent.interfaces must be non-empty"},
		{"[agent]\ninterfaces = [\"[\"]\n", "agent.interfaces: interface pattern"},
		{base + "[agent.bpf]\nsample_rte = 1\n", "unknown config key: agent.bpf.sample_rte"},
		{base + "[agent.bpf]\nsample_rate = 0\n", "sample_rate must be > 0"},
		{base + "[agent.bpf]\nring_buf_size = -4096\n", "ring_buf_size must be > 0, or 0 to derive it"},
		{base + "[agent.bpf]\nring_buf_size = 12345\n", "ring_buf_size must be a power of two"},
		{base + "[agent.bpf]\nring_buf_size = " + halfPage + "\n", "ring_buf_size must be a multiple of the page size"},
		// a batch of half the ring and more leaves the reader no room
		{base + "[agent.bpf]\nring_buf_size = 65536\nwakeup_batch = 1024\n", "wakeup_batch must be at most half the 1024 events"},
		{base + "[agent.bpf]\nring_buf_size = 16384\nwakeup_batch = 129\n", "wakeup_batch must be at most half the 256 events"},
		{base + "[agent.bpf]\nwakeup_batch = 4000000000\n", "wakeup_batch must be at most half the 1048576 events"},
		{base + "[agent.bpf]\niface_slots = -1\n", "iface_slots must be between 0 and 256"},
		{base + "[agent.bpf]\niface_slots = 257\n", "iface_slots must be between 0 and 256"},
		{base + "[agent.bpf]\niface_stats_size = -1\n", "iface_stats_size must be >= 0"},
		{base + "[agent.bpf]\nsample_rate = 2000\n", "max_sample_rate must be >= sample_rate"},
		{base + "[agent.bpf]\nmax_sample_rate = 0\n", "max_sample_rate must be >= sample_rate"},
		// the flow table, the label tuples and the ipfix queue are all sized
		// by max_flows, none of them has an unlimited size
		{base + "[agent.collector]\nmax_flows = 0\n", "max_flows must be > 0"},
		{base + "[agent.collector]\nmax_flows = -1\n", "max_flows must be > 0"},
		{base + "[agent.collector]\neviction_timeout = \"notaduration\"\n", "invalid duration"},
		{base + "[agent.collector]\neviction_timeout = \"1ns\"\n", "eviction_timeout must be >= 1s"},
		{base + "[agent.collector]\neviction_timeout = \"0s\"\n", "eviction_timeout must be >= 1s"},
		// a bare number is nanoseconds
		{base + "[agent.collector]\neviction_timeout = 5\n", "eviction_timeout must be >= 1s"},
		{base + "[agent.collector]\nactive_timeout = \"500ms\"\n", "active_timeout must be 0 or >= 1s"},
		{base + "[agent.prometheus]\nport = 0\n", "prometheus.port must be between 1 and 65535"},
		{base + "[agent.prometheus]\nport = -1\n", "prometheus.port must be between 1 and 65535"},
		{base + "[agent.prometheus]\nport = 70000\n", "prometheus.port must be between 1 and 65535"},
		{base + "[agent.ipfix]\nhost = \"127.0.0.1\"\nport = -1\n", "ipfix.port must be between 1 and 65535"},
		{base + "[agent.ipfix]\nhost = \"127.0.0.1\"\nport = 70000\n", "ipfix.port must be between 1 and 65535"},
		{base + "[agent.ipfix]\nport = 4739\n[agent.ipfix.bind]\nport = -1\n", "ipfix.bind.port must be between 0 and 65535"},
		{base + "[agent.ipfix]\nport = 4739\n[agent.ipfix.bind]\nport = 70000\n", "ipfix.bind.port must be between 0 and 65535"},
		{base + "[agent.ipfix.bind]\nhost = \"127.0.0.1\"\n", "ipfix.bind requires agent.ipfix.host or port"},
		{base + "[agent.ipfix]\ntemplate_refresh = \"notaduration\"\n", "invalid duration"},
		{base + "[agent.ipfix]\ntemplate_refresh = \"100ms\"\n", "template_refresh must be >= 1s"},
		{base + "[agent.ipfix]\ntemplate_refresh = \"0s\"\n", "template_refresh must be >= 1s"},
		{base + "[agent.ipfix]\nobservation_domain_id = 0\n", "observation_domain_id must be > 0"},
		{base + "[agent.ipfix]\nport = 4739\nmax_message_size = 0\n", "max_message_size must be between"},
		{base + "[agent.ipfix]\nmax_message_size = " + strconv.Itoa(MinIPFIXMaxMessageSize-1) + "\n", "max_message_size must be between"},
		{base + "[agent.ipfix]\nmax_message_size = 70000\n", "max_message_size must be between"},
	} {
		if _, err := Parse([]byte(tc.data)); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Fatalf("config\n%s\nerror = %v, want %q", tc.data, err, tc.err)
		}
	}
}

func TestInterfaceMatcher(t *testing.T) {
	match, err := InterfaceMatcher([]string{"lo", "eth[0-9]+", "wg0|wg1"})
	if err != nil {
		t.Fatalf("InterfaceMatcher: %v", err)
	}
	// every pattern, each alternative included, matches a name as a whole
	for name, want := range map[string]bool{
		"lo":   true,
		"lo0":  false,
		"xlo":  false,
		"eth0": true,
		"eth":  false,
		"wg1":  true,
		"wg0x": false,
		"xwg1": false,
	} {
		if got := match(name); got != want {
			t.Errorf("match(%q) = %v, want %v", name, got, want)
		}
	}

	if _, err := InterfaceMatcher([]string{"["}); err == nil {
		t.Fatal("should fail on invalid regex")
	}
}

func TestGlobPatterns(t *testing.T) {
	patterns := []string{"eth0", "ranet*", "ranet.*", `eth\d*`, "eth[0-9]*", "wg?", "br-*", "(eth|ens)[0-9]+", "ra(net)*", "["}
	want := []string{"ranet*", "wg?", "br-*"}
	if got := GlobPatterns(patterns); !slices.Equal(got, want) {
		t.Fatalf("GlobPatterns = %q, want %q", got, want)
	}
}

func TestUnmatchedPatterns(t *testing.T) {
	names := []string{"lo", "eth0", "ranet0a1b2"}
	// ranet* is the regex rane followed by any number of t
	patterns := []string{"eth0", "ranet*", "ranet.*", "wg[0-9]+", "["}
	want := []string{"ranet*", "wg[0-9]+", "["}
	if got := UnmatchedPatterns(patterns, names); !slices.Equal(got, want) {
		t.Fatalf("UnmatchedPatterns = %q, want %q", got, want)
	}
}

func TestRingBufSizeForHalvesPerDoublingDownToTheFloor(t *testing.T) {
	for _, tc := range []struct {
		n    uint32
		want int
	}{{1, 262144}, {2, 131072}, {3, 131072}, {4, 65536}, {8, 65536}, {10, 65536}, {16, 65536}, {100, 65536}, {1000, 65536}} {
		if got := RingBufSizeFor(tc.n); got != max(tc.want, os.Getpagesize()) {
			t.Fatalf("RingBufSizeFor(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}
