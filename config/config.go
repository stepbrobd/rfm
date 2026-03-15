package config

import (
	"fmt"
	"os"
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
	Prometheus PrometheusConfig `toml:"prometheus"`
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

// PrometheusConfig controls the Prometheus metrics endpoint.
type PrometheusConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
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
		Prometheus PrometheusConfig   `toml:"prometheus"`
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
	raw.Agent.Prometheus.Host = "::"
	raw.Agent.Prometheus.Port = 9669

	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Parse eviction timeout.
	evictionTimeout, err := time.ParseDuration(raw.Agent.Collector.EvictionTimeout)
	if err != nil {
		return nil, fmt.Errorf("parsing eviction_timeout %q: %w", raw.Agent.Collector.EvictionTimeout, err)
	}

	cfg := &Config{
		Agent: AgentConfig{
			Interfaces: raw.Agent.Interfaces,
			BPF:        raw.Agent.BPF,
			Collector: CollectorConfig{
				MaxFlows:        raw.Agent.Collector.MaxFlows,
				EvictionTimeout: evictionTimeout,
			},
			Prometheus: raw.Agent.Prometheus,
		},
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func validate(cfg *Config) error {
	a := &cfg.Agent

	if len(a.Interfaces) == 0 {
		return fmt.Errorf("agent.interfaces must be non-empty")
	}
	if a.BPF.SampleRate == 0 {
		return fmt.Errorf("agent.bpf.sample_rate must be > 0")
	}
	if a.BPF.RingBufSize <= 0 {
		return fmt.Errorf("agent.bpf.ring_buf_size must be > 0")
	}
	if a.Collector.MaxFlows < 0 {
		return fmt.Errorf("agent.collector.max_flows must be >= 0")
	}
	if a.Collector.EvictionTimeout <= 0 {
		return fmt.Errorf("agent.collector.eviction_timeout must be > 0")
	}
	if a.Prometheus.Port < 1 || a.Prometheus.Port > 65535 {
		return fmt.Errorf("agent.prometheus.port must be between 1 and 65535, got %d", a.Prometheus.Port)
	}

	return nil
}
