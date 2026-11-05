package config

import (
	"fmt"
	"math"
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
	SampleRate       uint32 `toml:"sample_rate"`
	RingBufSize      int    `toml:"ring_buf_size"`
	WakeupBatch      uint32 `toml:"wakeup_batch"`
	IfaceStatsSize   int    `toml:"iface_stats_size"`
	IfaceSlots       int    `toml:"iface_slots"`
	AdaptiveSampling bool   `toml:"adaptive_sampling"`
	MaxSampleRate    uint32 `toml:"max_sample_rate"`
	PinPath          string `toml:"pin_path"`
	SampledOnly      bool   `toml:"sampled_only"`
	StageEvents      uint32 `toml:"stage_events"`
}

// CollectorConfig controls flow collection and eviction
type CollectorConfig struct {
	MaxFlows        int           `toml:"max_flows"`
	EvictionTimeout time.Duration `toml:"eviction_timeout"`
	ActiveTimeout   time.Duration `toml:"active_timeout"`
}

// IPFIXConfig controls export to a single IPFIX collector
type IPFIXConfig struct {
	Host                string          `toml:"host"`
	Port                int             `toml:"port"`
	Bind                IPFIXBindConfig `toml:"bind"`
	TemplateRefresh     time.Duration   `toml:"template_refresh"`
	ObservationDomainID uint32          `toml:"observation_domain_id"`
	QueueSize           int             `toml:"-"`
	MaxMessageSize      int             `toml:"max_message_size"`
}

// IPFIXBindConfig controls the local UDP bind used by the IPFIX exporter
type IPFIXBindConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

// Enabled reports whether IPFIX export should be configured
func (c IPFIXConfig) Enabled() bool {
	return c.Host != "" || c.Port != 0
}

// Addr formats the collector address
func (c IPFIXConfig) Addr() string {
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

// Addr formats the listener address
func (c BMPConfig) Addr() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// RIBConfig controls the live RIB/BMP backend
type RIBConfig struct {
	BMP BMPConfig `toml:"bmp"`
}

// Parse decodes a TOML config, fills in the defaults and validates it
func Parse(data []byte) (*Config, error) {
	cfg := &Config{Agent: AgentConfig{
		BPF:        BPFConfig{SampleRate: defaultSampleRate, MaxSampleRate: defaultMaxSampleRate, StageEvents: defaultStageEvents},
		Collector:  CollectorConfig{MaxFlows: DefaultMaxFlows, EvictionTimeout: defaultEvictionTimeout, ActiveTimeout: defaultActiveTimeout},
		IPFIX:      IPFIXConfig{TemplateRefresh: defaultTemplateRefresh, ObservationDomainID: defaultObservationDomainID, MaxMessageSize: DefaultIPFIXMaxMessageSize},
		Prometheus: PrometheusConfig{Host: defaultHost, Port: defaultPrometheusPort},
	}}
	meta, err := toml.Decode(string(data), cfg)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown config key: %s", undecoded[0])
	}

	a := &cfg.Agent
	defaultEndpoint(&a.IPFIX.Host, &a.IPFIX.Port, defaultIPFIXPort)
	defaultEndpoint(&a.Enrich.RIB.BMP.Host, &a.Enrich.RIB.BMP.Port, defaultBMPPort)
	a.IPFIX.QueueSize = max(DefaultIPFIXQueueSize, a.Collector.MaxFlows)
	if a.BPF.RingBufSize == 0 && a.BPF.SampleRate > 0 {
		a.BPF.RingBufSize = RingBufSizeFor(a.BPF.SampleRate)
		// a set batch gets a ring that holds twice its events, as validate asks
		for uint64(a.BPF.RingBufSize) < 2*uint64(a.BPF.WakeupBatch)*ringRecordBytes && a.BPF.RingBufSize < maxDerivedRingBufSize {
			a.BPF.RingBufSize *= 2
		}
	}
	if a.BPF.WakeupBatch == 0 && a.BPF.RingBufSize > 0 {
		a.BPF.WakeupBatch = uint32(max(a.BPF.RingBufSize/ringRecordBytes/2, 1))
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// RingBufSizeFor returns the ring of each cpu for sample rate n, 256 KiB at rate 1
// and half as much for each doubling of the rate down to 64 KiB, so a ring holds
// about as long a burst of a cpu's packets up to rate 4, the floor keeps the
// derived wakeup batch at 512 events, and a ring is never less than a page
func RingBufSizeFor(n uint32) int {
	size := maxRingBufSize
	for r := uint32(2); r <= n && size > minRingBufSize; r *= 2 {
		size /= 2
	}
	return max(size, os.Getpagesize())
}

// defaultEndpoint fills in the host or the port of an endpoint that sets only
// the other
func defaultEndpoint(host *string, port *int, defaultPort int) {
	if *host == "" && *port == 0 {
		return
	}
	if *host == "" {
		*host = defaultHost
	}
	if *port == 0 {
		*port = defaultPort
	}
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
		return fmt.Errorf("agent.bpf.ring_buf_size must be > 0, or 0 to derive it from sample_rate, got %d", a.BPF.RingBufSize)
	}
	if a.BPF.RingBufSize&(a.BPF.RingBufSize-1) != 0 {
		return fmt.Errorf("agent.bpf.ring_buf_size must be a power of two, got %d", a.BPF.RingBufSize)
	}
	// the kernel takes the size as a 32 bit power of two
	if uint64(a.BPF.RingBufSize) > maxSetRingBufSize {
		return fmt.Errorf("agent.bpf.ring_buf_size must be at most %d, got %d", uint64(maxSetRingBufSize), a.BPF.RingBufSize)
	}
	// the kernel rejects ring buffers that are not a whole number of pages
	if page := os.Getpagesize(); a.BPF.RingBufSize%page != 0 {
		return fmt.Errorf("agent.bpf.ring_buf_size must be a multiple of the page size %d, got %d", page, a.BPF.RingBufSize)
	}
	// a batch that fills more than half the ring leaves the reader no room to catch up after the wakeup
	if records := uint32(a.BPF.RingBufSize / ringRecordBytes); a.BPF.WakeupBatch > records/2 {
		return fmt.Errorf("agent.bpf.wakeup_batch must be at most half the %d events a ring of %d bytes holds, got %d", records, a.BPF.RingBufSize, a.BPF.WakeupBatch)
	}
	if a.BPF.StageEvents < 1 || a.BPF.StageEvents > maxStageEvents {
		return fmt.Errorf("agent.bpf.stage_events must be between 1 and %d, got %d", maxStageEvents, a.BPF.StageEvents)
	}
	if a.BPF.IfaceStatsSize < 0 || uint64(a.BPF.IfaceStatsSize) > math.MaxUint32 {
		return fmt.Errorf("agent.bpf.iface_stats_size must be between 0 and %d, got %d", uint32(math.MaxUint32), a.BPF.IfaceStatsSize)
	}
	if a.BPF.IfaceSlots < 0 || a.BPF.IfaceSlots > maxIfaceSlots {
		return fmt.Errorf("agent.bpf.iface_slots must be between 0 and %d, got %d, 0 keeps the default", maxIfaceSlots, a.BPF.IfaceSlots)
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
	if a.IPFIX.MaxMessageSize < MinIPFIXMaxMessageSize || a.IPFIX.MaxMessageSize > 65535 {
		return fmt.Errorf("agent.ipfix.max_message_size must be between %d and 65535, got %d", MinIPFIXMaxMessageSize, a.IPFIX.MaxMessageSize)
	}
	if a.Prometheus.Port < 1 || a.Prometheus.Port > 65535 {
		return fmt.Errorf("agent.prometheus.port must be between 1 and 65535, got %d", a.Prometheus.Port)
	}
	if a.Enrich.RIB.BMP.Enabled() && (a.Enrich.RIB.BMP.Port < 1 || a.Enrich.RIB.BMP.Port > 65535) {
		return fmt.Errorf("agent.enrich.rib.bmp.port must be between 1 and 65535, got %d", a.Enrich.RIB.BMP.Port)
	}

	return nil
}
