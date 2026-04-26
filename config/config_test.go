package config

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"ysun.co/rfm/testutil"
)

func writeTOML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFull(t *testing.T) {
	path := writeTOML(t, `
	[agent]
	interfaces = ["eth0", "tailscale0"]

[agent.bpf]
sample_rate = 50
ring_buf_size = 131072

[agent.collector]
max_flows = 1024
eviction_timeout = "10s"

	[agent.prometheus]
	host = "127.0.0.1"
	port = 8080

	[agent.enrich.mmdb]
	asn_db = "/tmp/asn.mmdb"
	city_db = "/tmp/city.mmdb"

	[agent.enrich.rib.bmp]
	host = "127.0.0.1"
	port = 11019
	`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Agent.Interfaces) != 2 || cfg.Agent.Interfaces[0] != "eth0" || cfg.Agent.Interfaces[1] != "tailscale0" {
		t.Fatalf("interfaces = %v, want [eth0 tailscale0]", cfg.Agent.Interfaces)
	}
	if cfg.Agent.BPF.SampleRate != 50 {
		t.Fatalf("sample_rate = %d, want 50", cfg.Agent.BPF.SampleRate)
	}
	if cfg.Agent.BPF.RingBufSize != 131072 {
		t.Fatalf("ring_buf_size = %d, want 131072", cfg.Agent.BPF.RingBufSize)
	}
	if cfg.Agent.Collector.MaxFlows != 1024 {
		t.Fatalf("max_flows = %d, want 1024", cfg.Agent.Collector.MaxFlows)
	}
	if cfg.Agent.Collector.EvictionTimeout != 10*time.Second {
		t.Fatalf("eviction_timeout = %v, want 10s", cfg.Agent.Collector.EvictionTimeout)
	}
	if cfg.Agent.Prometheus.Host != "127.0.0.1" {
		t.Fatalf("host = %q, want 127.0.0.1", cfg.Agent.Prometheus.Host)
	}
	if cfg.Agent.Prometheus.Port != 8080 {
		t.Fatalf("port = %d, want 8080", cfg.Agent.Prometheus.Port)
	}
	if cfg.Agent.Enrich.MMDB.ASNDB != "/tmp/asn.mmdb" {
		t.Fatalf("asn_db = %q, want /tmp/asn.mmdb", cfg.Agent.Enrich.MMDB.ASNDB)
	}
	if cfg.Agent.Enrich.MMDB.CityDB != "/tmp/city.mmdb" {
		t.Fatalf("city_db = %q, want /tmp/city.mmdb", cfg.Agent.Enrich.MMDB.CityDB)
	}
	if cfg.Agent.Enrich.RIB.BMP.Host != "127.0.0.1" {
		t.Fatalf("bmp.host = %q, want 127.0.0.1", cfg.Agent.Enrich.RIB.BMP.Host)
	}
	if cfg.Agent.Enrich.RIB.BMP.Port != 11019 {
		t.Fatalf("bmp.port = %d, want 11019", cfg.Agent.Enrich.RIB.BMP.Port)
	}
}

func TestLoadDefaults(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Agent.BPF.SampleRate != 100 {
		t.Fatalf("sample_rate = %d, want 100", cfg.Agent.BPF.SampleRate)
	}
	if cfg.Agent.BPF.RingBufSize != 262144 {
		t.Fatalf("ring_buf_size = %d, want 262144", cfg.Agent.BPF.RingBufSize)
	}
	if cfg.Agent.BPF.WakeupBatch != 64 {
		t.Fatalf("wakeup_batch default = %d, want 64", cfg.Agent.BPF.WakeupBatch)
	}
	if cfg.Agent.Collector.MaxFlows != 65536 {
		t.Fatalf("max_flows = %d, want 65536", cfg.Agent.Collector.MaxFlows)
	}
	if cfg.Agent.Collector.EvictionTimeout != 30*time.Second {
		t.Fatalf("eviction_timeout = %v, want 30s", cfg.Agent.Collector.EvictionTimeout)
	}
	if cfg.Agent.Prometheus.Host != "::1" {
		t.Fatalf("host = %q, want ::1", cfg.Agent.Prometheus.Host)
	}
	if cfg.Agent.Prometheus.Port != 9669 {
		t.Fatalf("port = %d, want 9669", cfg.Agent.Prometheus.Port)
	}
	if cfg.Agent.IPFIX.Host != "" {
		t.Fatalf("ipfix.host = %q, want empty", cfg.Agent.IPFIX.Host)
	}
	if cfg.Agent.IPFIX.Port != 0 {
		t.Fatalf("ipfix.port = %d, want 0", cfg.Agent.IPFIX.Port)
	}
}

func TestLoadRIBBMPDefaultsHost(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.enrich.rib.bmp]
port = 11019
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Agent.Enrich.RIB.BMP.Host != "::1" {
		t.Fatalf("bmp.host = %q, want ::1", cfg.Agent.Enrich.RIB.BMP.Host)
	}
	if cfg.Agent.Enrich.RIB.BMP.Port != 11019 {
		t.Fatalf("bmp.port = %d, want 11019", cfg.Agent.Enrich.RIB.BMP.Port)
	}
}

func TestLoadRIBBMPDefaultsPort(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.enrich.rib.bmp]
host = "127.0.0.1"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Agent.Enrich.RIB.BMP.Host != "127.0.0.1" {
		t.Fatalf("bmp.host = %q, want 127.0.0.1", cfg.Agent.Enrich.RIB.BMP.Host)
	}
	if cfg.Agent.Enrich.RIB.BMP.Port != 11019 {
		t.Fatalf("bmp.port = %d, want 11019", cfg.Agent.Enrich.RIB.BMP.Port)
	}
}

func TestLoadIPFIXDefaultsHost(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.ipfix]
port = 4739
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Agent.IPFIX.Host != "::1" {
		t.Fatalf("ipfix.host = %q, want ::1", cfg.Agent.IPFIX.Host)
	}
	if cfg.Agent.IPFIX.Port != 4739 {
		t.Fatalf("ipfix.port = %d, want 4739", cfg.Agent.IPFIX.Port)
	}
}

func TestLoadIPFIXDefaultsPort(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.ipfix]
host = "127.0.0.1"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Agent.IPFIX.Host != "127.0.0.1" {
		t.Fatalf("ipfix.host = %q, want 127.0.0.1", cfg.Agent.IPFIX.Host)
	}
	if cfg.Agent.IPFIX.Port != 4739 {
		t.Fatalf("ipfix.port = %d, want 4739", cfg.Agent.IPFIX.Port)
	}
}

func TestLoadIPFIXBind(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.ipfix]
host = "192.0.2.10"
port = 2055

[agent.ipfix.bind]
host = "192.0.2.20"
port = 0
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Agent.IPFIX.Bind.Host != "192.0.2.20" {
		t.Fatalf("ipfix.bind.host = %q, want 192.0.2.20", cfg.Agent.IPFIX.Bind.Host)
	}
	if cfg.Agent.IPFIX.Bind.Port != 0 {
		t.Fatalf("ipfix.bind.port = %d, want 0", cfg.Agent.IPFIX.Bind.Port)
	}
}

func TestLoadMissingInterfaces(t *testing.T) {
	path := writeTOML(t, `
[agent]

[agent.bpf]
sample_rate = 100
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing interfaces")
	}
}

func TestLoadEmptyInterfaces(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = []
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty interfaces")
	}
}

func TestLoadBadSampleRate(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.bpf]
sample_rate = 0
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for sample_rate=0")
	}
}

func TestLoadWakeupBatch(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.bpf]
wakeup_batch = 256
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.BPF.WakeupBatch != 256 {
		t.Fatalf("wakeup_batch = %d, want 256", cfg.Agent.BPF.WakeupBatch)
	}
}

func TestLoadIfaceStatsSize(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.bpf]
iface_stats_size = 8192
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.BPF.IfaceStatsSize != 8192 {
		t.Fatalf("iface_stats_size = %d, want 8192", cfg.Agent.BPF.IfaceStatsSize)
	}
}

func TestLoadIfaceStatsSizeDefault(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.BPF.IfaceStatsSize != 0 {
		t.Fatalf("iface_stats_size default = %d, want 0 (auto)", cfg.Agent.BPF.IfaceStatsSize)
	}
}

func TestLoadNegativeIfaceStatsSize(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.bpf]
iface_stats_size = -1
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for negative iface_stats_size")
	}
}

func TestLoadZeroWakeupBatch(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.bpf]
wakeup_batch = 0
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for wakeup_batch = 0")
	}
}

func TestLoadRingBufSizeMustBePowerOfTwo(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.bpf]
ring_buf_size = 12345
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for non-power-of-two ring_buf_size")
	}
}

func TestLoadBadEvictionTimeout(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.collector]
eviction_timeout = "notaduration"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unparseable eviction_timeout")
	}
}

func TestLoadSubSecondEvictionTimeout(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.collector]
eviction_timeout = "1ns"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for sub-second eviction_timeout")
	}
}

func TestLoadBadPort(t *testing.T) {
	for _, port := range []int{0, -1, 70000} {
		path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.prometheus]
port = `+strconv.Itoa(port)+`
`)

		_, err := Load(path)
		if err == nil {
			t.Fatalf("expected error for port=%d", port)
		}
	}
}

func TestLoadBadIPFIXPort(t *testing.T) {
	for _, port := range []int{-1, 70000} {
		path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.ipfix]
host = "127.0.0.1"
port = `+strconv.Itoa(port)+`
`)

		_, err := Load(path)
		if err == nil {
			t.Fatalf("expected error for ipfix port=%d", port)
		}
	}
}

func TestLoadBadIPFIXBindPort(t *testing.T) {
	for _, port := range []int{-1, 70000} {
		path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.ipfix]
host = "127.0.0.1"
port = 4739

[agent.ipfix.bind]
host = "127.0.0.1"
port = `+strconv.Itoa(port)+`
`)

		_, err := Load(path)
		if err == nil {
			t.Fatalf("expected error for ipfix.bind.port=%d", port)
		}
	}
}

func TestLoadIPFIXTemplateRefreshAndODID(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.ipfix]
host = "127.0.0.1"
port = 4739
template_refresh = "30s"
observation_domain_id = 42
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.IPFIX.TemplateRefresh != 30*time.Second {
		t.Fatalf("template_refresh = %v, want 30s", cfg.Agent.IPFIX.TemplateRefresh)
	}
	if cfg.Agent.IPFIX.ObservationDomainID != 42 {
		t.Fatalf("observation_domain_id = %d, want 42", cfg.Agent.IPFIX.ObservationDomainID)
	}
}

func TestLoadIPFIXDefaultsTemplateRefreshAndODID(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.IPFIX.TemplateRefresh != 60*time.Second {
		t.Fatalf("template_refresh default = %v, want 60s", cfg.Agent.IPFIX.TemplateRefresh)
	}
	if cfg.Agent.IPFIX.ObservationDomainID != 1 {
		t.Fatalf("observation_domain_id default = %d, want 1", cfg.Agent.IPFIX.ObservationDomainID)
	}
}

func TestLoadBadIPFIXTemplateRefresh(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.ipfix]
template_refresh = "notaduration"
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unparseable template_refresh")
	}
}

func TestLoadSubSecondIPFIXTemplateRefresh(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.ipfix]
template_refresh = "100ms"
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected error for sub-second template_refresh")
	}
}

func TestLoadZeroIPFIXObservationDomainID(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.ipfix]
observation_domain_id = 0
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected error for observation_domain_id = 0")
	}
}

func TestLoadIPFIXBindWithoutCollector(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.ipfix.bind]
host = "127.0.0.1"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for ipfix.bind without collector")
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := Load("/tmp/does-not-exist-rfm-config.toml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestResolveMatchAll(t *testing.T) {
	ifaces, err := ResolveInterfaces([]string{".*"})
	if err != nil {
		t.Fatalf("ResolveInterfaces: %v", err)
	}
	if len(ifaces) == 0 {
		t.Fatal(".* resolved to zero interfaces")
	}
}

func TestResolveExactName(t *testing.T) {
	loName := testutil.LoopbackName(t)

	ifaces, err := ResolveInterfaces([]string{loName})
	if err != nil {
		t.Fatalf("ResolveInterfaces: %v", err)
	}
	if len(ifaces) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(ifaces))
	}
	if ifaces[0].Name != loName {
		t.Fatalf("matched %q, want %q", ifaces[0].Name, loName)
	}
}

func TestResolveAnchoredExactNotPrefix(t *testing.T) {
	loName := testutil.LoopbackName(t)

	// the anchored regex for "lo" must not match "lo0", and vice versa
	other := loName + "x"
	ifaces, err := ResolveInterfaces([]string{other})
	if err == nil && len(ifaces) > 0 {
		t.Fatalf("anchored pattern %q matched unexpected interfaces: %v", other, ifaces)
	}
}

func TestResolveNoMatch(t *testing.T) {
	_, err := ResolveInterfaces([]string{"doesnotexist999"})
	if err == nil {
		t.Fatal("should fail when no interface matches")
	}
}

func TestResolveBadRegex(t *testing.T) {
	_, err := ResolveInterfaces([]string{"["})
	if err == nil {
		t.Fatal("should fail on invalid regex")
	}
}

func TestResolveDedupAcrossPatterns(t *testing.T) {
	loName := testutil.LoopbackName(t)

	// the two patterns both match the loopback, but it should appear once
	ifaces, err := ResolveInterfaces([]string{loName, ".*"})
	if err != nil {
		t.Fatalf("ResolveInterfaces: %v", err)
	}
	seen := make(map[int]int)
	for _, iface := range ifaces {
		seen[iface.Index]++
	}
	for idx, count := range seen {
		if count > 1 {
			t.Fatalf("interface index %d returned %d times", idx, count)
		}
	}
}

func TestLoadUnknownKey(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.bpf]
sample_rte = 1
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown key sample_rte")
	}
}

func TestLoadInvalidInterfaceRegex(t *testing.T) {
	path := writeTOML(t, `
[agent]
interfaces = ["["]
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid interface regex")
	}
}
