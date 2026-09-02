//go:build linux

package probe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// ifaceLinks are the two tcx links of one attached interface
type ifaceLinks struct {
	ingress link.Link
	egress  link.Link
}

type Probe struct {
	objs *rfmObjects

	mu    sync.Mutex
	links map[int]ifaceLinks
}

func Load(cfg Config) (*Probe, error) {
	spec, err := loadRfm()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	if cfg.RingBufSize > 0 {
		if ms, ok := spec.Maps["rfm_flow_events"]; ok {
			ms.MaxEntries = uint32(cfg.RingBufSize)
		}
	}

	if cfg.IfaceStatsSize > 0 {
		if ms, ok := spec.Maps["rfm_iface_stats"]; ok {
			ms.MaxEntries = uint32(cfg.IfaceStatsSize)
		}
	}

	// a pinned counter map from a previous run is reused when its shape
	// still matches, so a restart or upgrade keeps the counters monotonic
	var opts ebpf.CollectionOptions
	var pinned *ebpf.Map
	if cfg.PinPath != "" {
		pinned, err = loadPinnedIfaceStats(cfg.PinPath, spec.Maps["rfm_iface_stats"])
		if err != nil {
			return nil, err
		}
		if pinned != nil {
			opts.MapReplacements = map[string]*ebpf.Map{"rfm_iface_stats": pinned}
		}
	}

	var objs rfmObjects
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		if pinned != nil {
			pinned.Close()
		}
		return nil, fmt.Errorf("load BPF: %w", err)
	}
	if pinned != nil {
		// the collection holds its own handle now
		pinned.Close()
	} else if cfg.PinPath != "" {
		if err := objs.RfmIfaceStats.Pin(pinPathFor(cfg.PinPath)); err != nil {
			objs.Close()
			return nil, fmt.Errorf("pin iface stats: %w", err)
		}
	}

	// write config into BPF map at load time
	cfgKey := uint32(0)
	cfgVal := rfmRfmConfig{
		SampleRate:  cfg.SampleRate,
		Flags:       cfg.Flags,
		WakeupBatch: cfg.WakeupBatch,
	}
	if err := objs.RfmConfig.Update(cfgKey, cfgVal, ebpf.UpdateAny); err != nil {
		objs.Close()
		return nil, fmt.Errorf("write config: %w", err)
	}

	return &Probe{objs: &objs, links: make(map[int]ifaceLinks)}, nil
}

func pinPathFor(dir string) string {
	return filepath.Join(dir, "rfm_iface_stats")
}

// loadPinnedIfaceStats returns the pinned counter map under dir when one
// exists and matches spec, a stale pin with another shape is removed
// it returns nil, nil when there is nothing to reuse
func loadPinnedIfaceStats(dir string, spec *ebpf.MapSpec) (*ebpf.Map, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create pin directory %q: %w", dir, err)
	}

	path := pinPathFor(dir)
	m, err := ebpf.LoadPinnedMap(path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load pinned iface stats %q: %w", path, err)
	}

	if m.Type() != spec.Type || m.KeySize() != spec.KeySize || m.ValueSize() != spec.ValueSize ||
		m.MaxEntries() != spec.MaxEntries {
		log.Warn("pinned iface stats do not match the configured map, starting fresh", "path", path)
		err := m.Unpin()
		m.Close()
		if err != nil {
			return nil, fmt.Errorf("unpin stale iface stats %q: %w", path, err)
		}
		return nil, nil
	}
	return m, nil
}

// Close detaches every interface and releases the programs and maps
// a pinned counter map stays in bpffs for the next run
func (p *Probe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error
	for ifindex, l := range p.links {
		errs = append(errs, l.ingress.Close(), l.egress.Close())
		delete(p.links, ifindex)
	}
	errs = append(errs, p.objs.Close())
	return errors.Join(errs...)
}

// Attached lists the interfaces the programs are attached to
func (p *Probe) Attached() []int {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]int, 0, len(p.links))
	for ifindex := range p.links {
		out = append(out, ifindex)
	}
	return out
}

// Detach removes the programs from ifindex and drops its counters, so a
// recreated interface starts from zero under its new index
// detaching an interface that is not attached is not an error
func (p *Probe) Detach(ifindex int) error {
	p.mu.Lock()
	l, ok := p.links[ifindex]
	if ok {
		delete(p.links, ifindex)
	}
	p.mu.Unlock()
	if !ok {
		return nil
	}

	err := errors.Join(l.ingress.Close(), l.egress.Close())
	if cerr := p.clearIfaceStats(ifindex); cerr != nil {
		err = errors.Join(err, cerr)
	}
	return err
}

// clearIfaceStats deletes every counter entry of ifindex
func (p *Probe) clearIfaceStats(ifindex int) error {
	var key rfmRfmIfaceKey
	var vals []rfmRfmIfaceValue
	var keys []rfmRfmIfaceKey
	iter := p.objs.RfmIfaceStats.Iterate()
	for iter.Next(&key, &vals) {
		if key.Ifindex == uint32(ifindex) {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate iface stats: %w", err)
	}
	for _, k := range keys {
		if err := p.objs.RfmIfaceStats.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete iface stats %d: %w", ifindex, err)
		}
	}
	return nil
}

func (p *Probe) SampleRate() (uint32, error) {
	key := uint32(0)
	var cfg rfmRfmConfig
	if err := p.objs.RfmConfig.Lookup(key, &cfg); err != nil {
		return 0, fmt.Errorf("read config: %w", err)
	}
	return cfg.SampleRate, nil
}

// SetSampleRate changes the 1-in-N sampling of the running programs
// the config map is read per packet, so the change applies at once without
// detaching or reloading anything
func (p *Probe) SetSampleRate(n uint32) error {
	if n == 0 {
		return fmt.Errorf("sample rate must be > 0")
	}
	key := uint32(0)
	var cfg rfmRfmConfig
	if err := p.objs.RfmConfig.Lookup(key, &cfg); err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	cfg.SampleRate = n
	if err := p.objs.RfmConfig.Update(key, cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func (p *Probe) IfaceStats() *ebpf.Map {
	return p.objs.RfmIfaceStats
}

func (p *Probe) FlowEvents() *ebpf.Map {
	return p.objs.RfmFlowEvents
}

func (p *Probe) FlowDrops() *ebpf.Map {
	return p.objs.RfmFlowDrops
}

// Attach installs both programs on ifindex as TCX links
// the ingress program is anchored at the head of the TCX chain and the egress
// program at its tail, so the counters see every frame the interface received
// before another program can drop or redirect it and every frame that is
// about to leave after other programs had their say, which is what the NIC
// counters measure as well
func (p *Probe) Attach(ifindex int) error {
	p.mu.Lock()
	_, attached := p.links[ifindex]
	p.mu.Unlock()
	if attached {
		return nil
	}

	ing, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   p.objs.RfmTcIngress,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Head(),
	})
	if err != nil {
		return fmt.Errorf("attach ingress on %d: %w", ifindex, err)
	}

	egr, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   p.objs.RfmTcEgress,
		Attach:    ebpf.AttachTCXEgress,
		Anchor:    link.Tail(),
	})
	if err != nil {
		ing.Close()
		return fmt.Errorf("attach egress on %d: %w", ifindex, err)
	}

	p.mu.Lock()
	p.links[ifindex] = ifaceLinks{ingress: ing, egress: egr}
	p.mu.Unlock()
	return nil
}
