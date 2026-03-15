package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if cfg.Agent.Collector.MaxFlows != 65536 {
		t.Fatalf("max_flows = %d, want 65536", cfg.Agent.Collector.MaxFlows)
	}
	if cfg.Agent.Collector.EvictionTimeout != 30*time.Second {
		t.Fatalf("eviction_timeout = %v, want 30s", cfg.Agent.Collector.EvictionTimeout)
	}
	if cfg.Agent.Prometheus.Host != "::" {
		t.Fatalf("host = %q, want ::", cfg.Agent.Prometheus.Host)
	}
	if cfg.Agent.Prometheus.Port != 9669 {
		t.Fatalf("port = %d, want 9669", cfg.Agent.Prometheus.Port)
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

func TestLoadBadPort(t *testing.T) {
	for _, port := range []int{0, -1, 70000} {
		path := writeTOML(t, `
[agent]
interfaces = ["eth0"]

[agent.prometheus]
port = `+itoa(port)+`
`)

		_, err := Load(path)
		if err == nil {
			t.Fatalf("expected error for port=%d", port)
		}
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := Load("/tmp/does-not-exist-rfm-config.toml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestResolveWildcard(t *testing.T) {
	indices, err := ResolveInterfaces([]string{"*"})
	if err != nil {
		t.Fatalf("ResolveInterfaces: %v", err)
	}
	if len(indices) == 0 {
		t.Fatal("wildcard resolved to zero interfaces")
	}
	for _, idx := range indices {
		iface, _ := net.InterfaceByIndex(idx)
		if iface != nil && iface.Flags&net.FlagLoopback != 0 {
			t.Errorf("wildcard should skip loopback, got %s", iface.Name)
		}
	}
}

func TestResolveNamed(t *testing.T) {
	indices, err := ResolveInterfaces([]string{"lo"})
	if err != nil {
		t.Fatalf("ResolveInterfaces: %v", err)
	}
	if len(indices) != 1 {
		t.Fatalf("got %d indices, want 1", len(indices))
	}
}

func TestResolveBadInterface(t *testing.T) {
	_, err := ResolveInterfaces([]string{"doesnotexist999"})
	if err == nil {
		t.Fatal("should fail on nonexistent interface")
	}
}

func TestResolveWildcardWithOthers(t *testing.T) {
	_, err := ResolveInterfaces([]string{"*", "eth0"})
	if err == nil {
		t.Fatal("should fail when * is mixed with named interfaces")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
