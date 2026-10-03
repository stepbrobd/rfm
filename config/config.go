package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the top-level configuration
type Config struct {
	Agent AgentConfig `toml:"agent"`
}

// AgentConfig holds all agent-level settings
type AgentConfig struct {
	Interfaces []string         `toml:"interfaces"`
	BPF        BPFConfig        `toml:"bpf"`
	Collector  CollectorConfig  `toml:"collector"`
	IPFIX      IPFIXConfig      `toml:"ipfix"`
	Prometheus PrometheusConfig `toml:"prometheus"`
	Enrich     EnrichConfig     `toml:"enrich"`
	Control    ControlConfig    `toml:"control"`
}

// ControlConfig controls the unix socket the rfm command line talks to
type ControlConfig struct {
	// Socket is the path of the control socket, empty disables it
	Socket string `toml:"socket"`
}

// BPFConfig controls the eBPF probe
type BPFConfig struct {
	SampleRate     uint32 `toml:"sample_rate"`
	RingBufSize    int    `toml:"ring_buf_size"`
	WakeupBatch    uint32 `toml:"wakeup_batch"`
	IfaceStatsSize int    `toml:"iface_stats_size"`
	// AdaptiveSampling lets the collector raise the sample rate while the
	// ring buffer drops events and lower it back once the drops stop
	AdaptiveSampling bool `toml:"adaptive_sampling"`
	// MaxSampleRate caps the adaptive sample rate and any rate set with
	// rfm set sample-rate
	MaxSampleRate uint32 `toml:"max_sample_rate"`
	// PinPath is a bpffs directory that keeps the interface counters across
	// restarts, empty keeps them private to the process
	PinPath string `toml:"pin_path"`
}

// CollectorConfig controls flow collection and eviction
type CollectorConfig struct {
	MaxFlows        int           `toml:"-"`
	EvictionTimeout time.Duration `toml:"-"`
	ActiveTimeout   time.Duration `toml:"-"`
}

// DefaultMaxFlows is the flow table size when max_flows is not set
const DefaultMaxFlows = 65536

// IPFIXConfig controls export to a single IPFIX collector
type IPFIXConfig struct {
	Host                string
	Port                int
	Bind                IPFIXBindConfig
	TemplateRefresh     time.Duration
	ObservationDomainID uint32
	// QueueSize bounds the records waiting for the sender goroutine, an
	// eviction sweep can hand the exporter every flow in the table at once,
	// so the default is max_flows or DefaultIPFIXQueueSize, whichever is
	// larger
	QueueSize int
	// FlushInterval is how long the sender gathers records before a message
	// goes out when fewer than a full message are waiting
	FlushInterval time.Duration
	// MaxMessageSize caps one IPFIX message in bytes, kept under the path
	// mtu so a message never fragments
	MaxMessageSize int
}

// default exporter sizing
const (
	DefaultIPFIXQueueSize      = 4096
	DefaultIPFIXFlushInterval  = time.Second
	DefaultIPFIXMaxMessageSize = 1200
)

// IPFIXBindConfig controls the local UDP bind used by the IPFIX exporter
type IPFIXBindConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

// Enabled reports whether IPFIX export should be configured
func (c IPFIXConfig) Enabled() bool {
	return c.Host != "" || c.Port != 0
}

// WithDefaults fills in collector defaults when IPFIX export is enabled
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
	if c.QueueSize == 0 {
		c.QueueSize = DefaultIPFIXQueueSize
	}
	if c.FlushInterval == 0 {
		c.FlushInterval = DefaultIPFIXFlushInterval
	}
	if c.MaxMessageSize == 0 {
		c.MaxMessageSize = DefaultIPFIXMaxMessageSize
	}
	return c
}

// Addr formats the collector address
func (c IPFIXConfig) Addr() string {
	c = c.WithDefaults()
	if !c.Enabled() {
		return ""
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// Enabled reports whether a local source bind should be configured
func (c IPFIXBindConfig) Enabled() bool {
	return c.Host != "" || c.Port != 0
}

// Addr formats the local bind address
func (c IPFIXBindConfig) Addr() string {
	if !c.Enabled() {
		return ""
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// PrometheusConfig controls the Prometheus metrics endpoint
type PrometheusConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

// EnrichConfig controls optional flow enrichment backends
type EnrichConfig struct {
	MMDB MMDBConfig `toml:"mmdb"`
	RIB  RIBConfig  `toml:"rib"`
}

// MMDBConfig controls MaxMind/DB-IP database lookups
type MMDBConfig struct {
	ASNDB  string `toml:"asn_db"`
	CityDB string `toml:"city_db"`
}

// BMPConfig controls the live BMP listener for the RIB backend
type BMPConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

// Enabled reports whether the BMP listener should be configured
func (c BMPConfig) Enabled() bool {
	return c.Host != "" || c.Port != 0
}

// WithDefaults fills in BMP defaults when the backend is enabled
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

// Addr formats the listener address
func (c BMPConfig) Addr() string {
	c = c.WithDefaults()
	if !c.Enabled() {
		return ""
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// RIBConfig controls the live RIB/BMP backend
type RIBConfig struct {
	BMP BMPConfig `toml:"bmp"`
}

// rawCollectorConfig mirrors CollectorConfig with string-typed fields for TOML decoding
type rawCollectorConfig struct {
	MaxFlows        int    `toml:"max_flows"`
	EvictionTimeout string `toml:"eviction_timeout"`
	ActiveTimeout   string `toml:"active_timeout"`
}

// rawIPFIXConfig mirrors IPFIXConfig with string-typed fields for TOML decoding
type rawIPFIXConfig struct {
	Host                string          `toml:"host"`
	Port                int             `toml:"port"`
	Bind                IPFIXBindConfig `toml:"bind"`
	TemplateRefresh     string          `toml:"template_refresh"`
	ObservationDomainID uint32          `toml:"observation_domain_id"`
	QueueSize           int             `toml:"queue_size"`
	FlushInterval       string          `toml:"flush_interval"`
	MaxMessageSize      int             `toml:"max_message_size"`
}

// rawConfig is the wire format for TOML decoding, before duration parsing
type rawConfig struct {
	Agent struct {
		Interfaces []string           `toml:"interfaces"`
		BPF        BPFConfig          `toml:"bpf"`
		Collector  rawCollectorConfig `toml:"collector"`
		IPFIX      rawIPFIXConfig     `toml:"ipfix"`
		Prometheus PrometheusConfig   `toml:"prometheus"`
		Enrich     EnrichConfig       `toml:"enrich"`
		Control    ControlConfig      `toml:"control"`
	} `toml:"agent"`
}

// Load reads a TOML config file, applies defaults, parses durations, and validates
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	// start with defaults
	raw := rawConfig{}
	raw.Agent.BPF.SampleRate = 100
	raw.Agent.BPF.RingBufSize = 262144
	raw.Agent.BPF.WakeupBatch = 64
	raw.Agent.BPF.MaxSampleRate = 1000
	raw.Agent.Collector.MaxFlows = DefaultMaxFlows
	raw.Agent.Collector.EvictionTimeout = "30s"
	raw.Agent.Collector.ActiveTimeout = "60s"
	raw.Agent.IPFIX.TemplateRefresh = "60s"
	raw.Agent.IPFIX.ObservationDomainID = 1
	raw.Agent.IPFIX.FlushInterval = "1s"
	raw.Agent.IPFIX.MaxMessageSize = DefaultIPFIXMaxMessageSize
	raw.Agent.Prometheus.Host = "::1"
	raw.Agent.Prometheus.Port = 9669

	meta, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown config key: %s", undecoded[0])
	}

	// parse eviction timeout
	evictionTimeout, err := time.ParseDuration(raw.Agent.Collector.EvictionTimeout)
	if err != nil {
		return nil, fmt.Errorf("parsing eviction_timeout %q: %w", raw.Agent.Collector.EvictionTimeout, err)
	}

	activeTimeout, err := time.ParseDuration(raw.Agent.Collector.ActiveTimeout)
	if err != nil {
		return nil, fmt.Errorf("parsing active_timeout %q: %w", raw.Agent.Collector.ActiveTimeout, err)
	}

	templateRefresh, err := time.ParseDuration(raw.Agent.IPFIX.TemplateRefresh)
	if err != nil {
		return nil, fmt.Errorf("parsing ipfix.template_refresh %q: %w", raw.Agent.IPFIX.TemplateRefresh, err)
	}

	flushInterval, err := time.ParseDuration(raw.Agent.IPFIX.FlushInterval)
	if err != nil {
		return nil, fmt.Errorf("parsing ipfix.flush_interval %q: %w", raw.Agent.IPFIX.FlushInterval, err)
	}

	raw.Agent.Enrich.RIB.BMP = raw.Agent.Enrich.RIB.BMP.WithDefaults()
	queueSize := raw.Agent.IPFIX.QueueSize
	if queueSize == 0 {
		queueSize = max(DefaultIPFIXQueueSize, raw.Agent.Collector.MaxFlows)
	}
	ipfixCfg := IPFIXConfig{
		Host:                raw.Agent.IPFIX.Host,
		Port:                raw.Agent.IPFIX.Port,
		Bind:                raw.Agent.IPFIX.Bind,
		TemplateRefresh:     templateRefresh,
		ObservationDomainID: raw.Agent.IPFIX.ObservationDomainID,
		QueueSize:           queueSize,
		FlushInterval:       flushInterval,
		MaxMessageSize:      raw.Agent.IPFIX.MaxMessageSize,
	}.WithDefaults()

	cfg := &Config{
		Agent: AgentConfig{
			Interfaces: raw.Agent.Interfaces,
			BPF:        raw.Agent.BPF,
			Collector: CollectorConfig{
				MaxFlows:        raw.Agent.Collector.MaxFlows,
				EvictionTimeout: evictionTimeout,
				ActiveTimeout:   activeTimeout,
			},
			IPFIX:      ipfixCfg,
			Prometheus: raw.Agent.Prometheus,
			Enrich:     raw.Agent.Enrich,
			Control:    raw.Agent.Control,
		},
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// InterfaceMatcher compiles patterns into a predicate over interface names
// patterns are Go regular expressions, anchored full-string, for example
// ".*" matches every name and "eth.*" every name with the eth prefix
func InterfaceMatcher(patterns []string) (func(string) bool, error) {
	compiled, err := compileInterfacePatterns(patterns)
	if err != nil {
		return nil, err
	}
	return func(name string) bool {
		for _, re := range compiled {
			if re.MatchString(name) {
				return true
			}
		}
		return false
	}, nil
}

// GlobPatterns returns the patterns where * or ? repeats a single literal
// character, which reads as a shell glob, as a regular expression "ranet*"
// matches rane, ranet and ranettt but not ranet0
func GlobPatterns(patterns []string) []string {
	var globs []string
	for _, p := range patterns {
		re, err := syntax.Parse(p, syntax.Perl)
		if err == nil && repeatsLiteral(re) {
			globs = append(globs, p)
		}
	}
	return globs
}

func repeatsLiteral(re *syntax.Regexp) bool {
	if re.Op == syntax.OpStar || re.Op == syntax.OpQuest {
		if sub := re.Sub[0]; sub.Op == syntax.OpLiteral && len(sub.Rune) == 1 {
			return true
		}
	}
	return slices.ContainsFunc(re.Sub, repeatsLiteral)
}

// UnmatchedPatterns returns the patterns that match none of names, a
// pattern that does not compile matches nothing
func UnmatchedPatterns(patterns, names []string) []string {
	var unmatched []string
	for _, p := range patterns {
		match, err := InterfaceMatcher([]string{p})
		if err != nil || !slices.ContainsFunc(names, match) {
			unmatched = append(unmatched, p)
		}
	}
	return unmatched
}

func compileInterfacePatterns(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		re, err := regexp.Compile("^(?:" + p + ")$")
		if err != nil {
			return nil, fmt.Errorf("interface pattern %q: %w", p, err)
		}
		out[i] = re
	}
	return out, nil
}

func validate(cfg *Config) error {
	a := &cfg.Agent

	if len(a.Interfaces) == 0 {
		return fmt.Errorf("agent.interfaces must be non-empty")
	}
	if _, err := compileInterfacePatterns(a.Interfaces); err != nil {
		return fmt.Errorf("agent.interfaces: %w", err)
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
	// the kernel rejects ring buffers that are not a whole number of pages
	if page := os.Getpagesize(); a.BPF.RingBufSize%page != 0 {
		return fmt.Errorf("agent.bpf.ring_buf_size must be a multiple of the page size %d, got %d", page, a.BPF.RingBufSize)
	}
	if a.BPF.WakeupBatch == 0 {
		return fmt.Errorf("agent.bpf.wakeup_batch must be > 0")
	}
	if a.BPF.IfaceStatsSize < 0 {
		return fmt.Errorf("agent.bpf.iface_stats_size must be >= 0, got %d", a.BPF.IfaceStatsSize)
	}
	if a.BPF.MaxSampleRate < a.BPF.SampleRate {
		return fmt.Errorf("agent.bpf.max_sample_rate must be >= sample_rate, got %d < %d", a.BPF.MaxSampleRate, a.BPF.SampleRate)
	}
	if a.Collector.MaxFlows < 1 {
		return fmt.Errorf("agent.collector.max_flows must be > 0, got %d, the flow table has no unlimited size", a.Collector.MaxFlows)
	}
	if a.Collector.EvictionTimeout < time.Second {
		return fmt.Errorf("agent.collector.eviction_timeout must be >= 1s, got %v", a.Collector.EvictionTimeout)
	}
	if a.Collector.ActiveTimeout != 0 && a.Collector.ActiveTimeout < time.Second {
		return fmt.Errorf("agent.collector.active_timeout must be 0 or >= 1s, got %v", a.Collector.ActiveTimeout)
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
	if a.IPFIX.TemplateRefresh < time.Second {
		return fmt.Errorf("agent.ipfix.template_refresh must be >= 1s, got %v", a.IPFIX.TemplateRefresh)
	}
	if a.IPFIX.ObservationDomainID == 0 {
		return fmt.Errorf("agent.ipfix.observation_domain_id must be > 0")
	}
	if a.IPFIX.QueueSize < 1 {
		return fmt.Errorf("agent.ipfix.queue_size must be >= 1, got %d", a.IPFIX.QueueSize)
	}
	if a.IPFIX.FlushInterval < 10*time.Millisecond {
		return fmt.Errorf("agent.ipfix.flush_interval must be >= 10ms, got %v", a.IPFIX.FlushInterval)
	}
	if a.IPFIX.MaxMessageSize < 128 || a.IPFIX.MaxMessageSize > 65535 {
		return fmt.Errorf("agent.ipfix.max_message_size must be between 128 and 65535, got %d", a.IPFIX.MaxMessageSize)
	}
	if a.Prometheus.Port < 1 || a.Prometheus.Port > 65535 {
		return fmt.Errorf("agent.prometheus.port must be between 1 and 65535, got %d", a.Prometheus.Port)
	}
	if a.Enrich.RIB.BMP.Enabled() && (a.Enrich.RIB.BMP.Port < 1 || a.Enrich.RIB.BMP.Port > 65535) {
		return fmt.Errorf("agent.enrich.rib.bmp.port must be between 1 and 65535, got %d", a.Enrich.RIB.BMP.Port)
	}

	return nil
}
