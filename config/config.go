package config

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration.
type Config struct {
	Agent AgentConfig `toml:"agent"`
}

// AgentConfig holds all agent-level settings.
type AgentConfig struct {
	Interfaces []string         `toml:"interfaces"`
	BPF        BPFConfig        `toml:"bpf"`
	Collector  CollectorConfig  `toml:"collector"`
	IPFIX      IPFIXConfig      `toml:"ipfix"`
	Prometheus PrometheusConfig `toml:"prometheus"`
	Enrich     EnrichConfig     `toml:"enrich"`
}

// BPFConfig controls the eBPF probe.
type BPFConfig struct {
	SampleRate  uint32 `toml:"sample_rate"`
	RingBufSize int    `toml:"ring_buf_size"`
}

// CollectorConfig controls flow collection and eviction.
type CollectorConfig struct {
	MaxFlows        int           `toml:"-"`
	EvictionTimeout time.Duration `toml:"-"`
}

// IPFIXConfig controls export to a single IPFIX collector.
type IPFIXConfig struct {
	Host string          `toml:"host"`
	Port int             `toml:"port"`
	Bind IPFIXBindConfig `toml:"bind"`
}

// IPFIXBindConfig controls the local UDP bind used by the IPFIX exporter.
type IPFIXBindConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

// Enabled reports whether IPFIX export should be configured.
func (c IPFIXConfig) Enabled() bool {
	return c.Host != "" || c.Port != 0
}

// WithDefaults fills in collector defaults when IPFIX export is enabled.
func (c IPFIXConfig) WithDefaults() IPFIXConfig {
	if !c.Enabled() {
		return c
	}
	if c.Host == "" {
		c.Host = "::1"
	}
	if c.Port == 0 {
		c.Port = 4739
	}
	return c
}

// Addr formats the collector address.
func (c IPFIXConfig) Addr() string {
	c = c.WithDefaults()
	if !c.Enabled() {
		return ""
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// Enabled reports whether a local source bind should be configured.
func (c IPFIXBindConfig) Enabled() bool {
	return c.Host != "" || c.Port != 0
}

// Addr formats the local bind address.
func (c IPFIXBindConfig) Addr() string {
	if !c.Enabled() {
		return ""
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// PrometheusConfig controls the Prometheus metrics endpoint.
type PrometheusConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

// EnrichConfig controls optional flow enrichment backends.
type EnrichConfig struct {
	MMDB MMDBConfig `toml:"mmdb"`
	RIB  RIBConfig  `toml:"rib"`
}

// MMDBConfig controls MaxMind/DB-IP database lookups.
type MMDBConfig struct {
	ASNDB  string `toml:"asn_db"`
	CityDB string `toml:"city_db"`
}

// BMPConfig controls the live BMP listener for the RIB backend.
type BMPConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

// Enabled reports whether the BMP listener should be configured.
func (c BMPConfig) Enabled() bool {
	return c.Host != "" || c.Port != 0
}

// WithDefaults fills in BMP defaults when the backend is enabled.
func (c BMPConfig) WithDefaults() BMPConfig {
	if !c.Enabled() {
		return c
	}
	if c.Host == "" {
		c.Host = "::1"
	}
	if c.Port == 0 {
		c.Port = 11019
	}
	return c
}

// Addr formats the listener address.
func (c BMPConfig) Addr() string {
	c = c.WithDefaults()
	if !c.Enabled() {
		return ""
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// RIBConfig controls the live RIB/BMP backend.
type RIBConfig struct {
	BMP BMPConfig `toml:"bmp"`
}

// rawCollectorConfig mirrors CollectorConfig with string-typed fields for TOML decoding.
type rawCollectorConfig struct {
	MaxFlows        int    `toml:"max_flows"`
	EvictionTimeout string `toml:"eviction_timeout"`
}

// rawConfig is the wire format for TOML decoding, before duration parsing.
type rawConfig struct {
	Agent struct {
		Interfaces []string           `toml:"interfaces"`
		BPF        BPFConfig          `toml:"bpf"`
		Collector  rawCollectorConfig `toml:"collector"`
		IPFIX      IPFIXConfig        `toml:"ipfix"`
		Prometheus PrometheusConfig   `toml:"prometheus"`
		Enrich     EnrichConfig       `toml:"enrich"`
	} `toml:"agent"`
}

// Load reads a TOML config file, applies defaults, parses durations, and validates.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	// Start with defaults.
	raw := rawConfig{}
	raw.Agent.BPF.SampleRate = 100
	raw.Agent.BPF.RingBufSize = 262144
	raw.Agent.Collector.MaxFlows = 65536
	raw.Agent.Collector.EvictionTimeout = "30s"
	raw.Agent.IPFIX = IPFIXConfig{}
	raw.Agent.Prometheus.Host = "::1"
	raw.Agent.Prometheus.Port = 9669

	meta, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown config key: %s", undecoded[0])
	}

	// Parse eviction timeout.
	evictionTimeout, err := time.ParseDuration(raw.Agent.Collector.EvictionTimeout)
	if err != nil {
		return nil, fmt.Errorf("parsing eviction_timeout %q: %w", raw.Agent.Collector.EvictionTimeout, err)
	}

	raw.Agent.Enrich.RIB.BMP = raw.Agent.Enrich.RIB.BMP.WithDefaults()
	raw.Agent.IPFIX = raw.Agent.IPFIX.WithDefaults()

	cfg := &Config{
		Agent: AgentConfig{
			Interfaces: raw.Agent.Interfaces,
			BPF:        raw.Agent.BPF,
			Collector: CollectorConfig{
				MaxFlows:        raw.Agent.Collector.MaxFlows,
				EvictionTimeout: evictionTimeout,
			},
			IPFIX:      raw.Agent.IPFIX,
			Prometheus: raw.Agent.Prometheus,
			Enrich:     raw.Agent.Enrich,
		},
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ResolveInterfaces converts interface names to indices.
// ["*"] expands to all non-loopback interfaces.
// "*" cannot be mixed with named interfaces.
func ResolveInterfaces(names []string) ([]int, error) {
	if len(names) == 1 && names[0] == "*" {
		return resolveWildcard()
	}
	if slices.Contains(names, "*") {
		return nil, fmt.Errorf("\"*\" cannot be mixed with named interfaces")
	}
	indices := make([]int, 0, len(names))
	for _, name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", name, err)
		}
		indices = append(indices, iface.Index)
	}
	return indices, nil
}

func resolveWildcard() ([]int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var indices []int
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		indices = append(indices, iface.Index)
	}
	if len(indices) == 0 {
		return nil, fmt.Errorf("no non-loopback interfaces found")
	}
	return indices, nil
}

func validate(cfg *Config) error {
	a := &cfg.Agent

	if len(a.Interfaces) == 0 {
		return fmt.Errorf("agent.interfaces must be non-empty")
	}
	for _, name := range a.Interfaces {
		if name == "*" && len(a.Interfaces) > 1 {
			return fmt.Errorf("agent.interfaces: \"*\" cannot be mixed with named interfaces")
		}
	}
	seen := make(map[string]bool, len(a.Interfaces))
	for _, name := range a.Interfaces {
		if seen[name] {
			return fmt.Errorf("agent.interfaces: duplicate interface %q", name)
		}
		seen[name] = true
	}
	if a.BPF.SampleRate == 0 {
		return fmt.Errorf("agent.bpf.sample_rate must be > 0")
	}
	if a.BPF.RingBufSize <= 0 {
		return fmt.Errorf("agent.bpf.ring_buf_size must be > 0")
	}
	if a.BPF.RingBufSize&(a.BPF.RingBufSize-1) != 0 {
		return fmt.Errorf("agent.bpf.ring_buf_size must be a power of two, got %d", a.BPF.RingBufSize)
	}
	if a.Collector.MaxFlows < 0 {
		return fmt.Errorf("agent.collector.max_flows must be >= 0")
	}
	if a.Collector.EvictionTimeout < time.Second {
		return fmt.Errorf("agent.collector.eviction_timeout must be >= 1s, got %v", a.Collector.EvictionTimeout)
	}
	if a.IPFIX.Enabled() && (a.IPFIX.Port < 1 || a.IPFIX.Port > 65535) {
		return fmt.Errorf("agent.ipfix.port must be between 1 and 65535, got %d", a.IPFIX.Port)
	}
	if a.IPFIX.Bind.Enabled() && !a.IPFIX.Enabled() {
		return fmt.Errorf("agent.ipfix.bind requires agent.ipfix.host or port")
	}
	if a.IPFIX.Bind.Port < 0 || a.IPFIX.Bind.Port > 65535 {
		return fmt.Errorf("agent.ipfix.bind.port must be between 0 and 65535, got %d", a.IPFIX.Bind.Port)
	}
	if a.Prometheus.Port < 1 || a.Prometheus.Port > 65535 {
		return fmt.Errorf("agent.prometheus.port must be between 1 and 65535, got %d", a.Prometheus.Port)
	}
	if a.Enrich.RIB.BMP.Enabled() && (a.Enrich.RIB.BMP.Port < 1 || a.Enrich.RIB.BMP.Port > 65535) {
		return fmt.Errorf("agent.enrich.rib.bmp.port must be between 1 and 65535, got %d", a.Enrich.RIB.BMP.Port)
	}

	return nil
}
