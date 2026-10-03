//go:build linux

package probe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ifaceLinks are the two tcx links of one attached interface
type ifaceLinks struct {
	name    string
	ingress link.Link
	egress  link.Link
}

type Probe struct {
	objs *rfmObjects

	mu    sync.Mutex
	links map[int]ifaceLinks
	// skipped holds the matching links Watch left alone because of their
	// link type, so their warning is logged once
	skipped map[int]bool
	// pending holds the names of the matching links whose attach failed for
	// another reason than their removal, Watch tries them again
	pending map[int]string

	watchState WatchState

	// rcvbuf overrides the receive buffer of the link subscription when
	// set, tests shrink it to make the socket overflow
	rcvbuf int
	// mangle, when set, sees the type and payload of every received link
	// message before the watcher reads them, tests corrupt one
	mangle func(typ uint16, data []byte)
}

func Load(cfg Config) (*Probe, error) {
	if cfg.WakeupBatch == 0 {
		return nil, errors.New("wakeup batch must be > 0")
	}

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

	// a pinned counter map from a previous run is reused, so a restart or
	// upgrade keeps the counters monotonic, and one of another shape, size
	// or flags fails the load
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

	return &Probe{objs: &objs, links: make(map[int]ifaceLinks), skipped: make(map[int]bool), pending: make(map[int]string)}, nil
}

func pinPathFor(dir string) string {
	return filepath.Join(dir, "rfm_iface_stats")
}

// loadPinnedIfaceStats returns the pinned counter map under dir, nil when
// there is none yet
// a pin the loader would refuse is an error that names the difference, the
// pin stays with its counters until it is removed or the host reboots
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

	// the same check the loader runs on a replacement map
	if err := spec.Compatible(m); err != nil {
		m.Close()
		return nil, fmt.Errorf("pinned iface stats %q do not match the configured map, remove the pin file or reboot to start the counters from zero: %w", path, err)
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
// recreated interface starts from zero under its new index, Watch detaches
// the links that go itself and only tests call Detach
// detaching an interface that is not attached is not an error
func (p *Probe) Detach(ifindex int) error {
	_, _, err := p.detach(ifindex)
	return err
}

// detach is Detach reporting the name the interface was attached under and
// whether it was attached
func (p *Probe) detach(ifindex int) (string, bool, error) {
	p.mu.Lock()
	l, ok := p.links[ifindex]
	if ok {
		delete(p.links, ifindex)
	}
	p.mu.Unlock()
	if !ok {
		return "", false, nil
	}

	err := errors.Join(l.ingress.Close(), l.egress.Close())
	if cerr := p.clearIfaceStats(ifindex); cerr != nil {
		err = errors.Join(err, cerr)
	}
	return l.name, true, err
}

// clearIfaceStats deletes every counter entry of ifindex
func (p *Probe) clearIfaceStats(ifindex int) error {
	return p.deleteIfaceStats(func(i uint32) bool { return i == uint32(ifindex) })
}

// pruneIfaceStats deletes the counter entries of every interface that is
// neither attached nor pending
func (p *Probe) pruneIfaceStats() error {
	p.mu.Lock()
	keep := make(map[uint32]bool, len(p.links)+len(p.pending))
	for ifindex := range p.links {
		keep[uint32(ifindex)] = true
	}
	for ifindex := range p.pending {
		keep[uint32(ifindex)] = true
	}
	p.mu.Unlock()
	return p.deleteIfaceStats(func(i uint32) bool { return !keep[i] })
}

// deleteIfaceStats deletes the counter entries whose ifindex drop accepts
func (p *Probe) deleteIfaceStats(drop func(ifindex uint32) bool) error {
	var key rfmRfmIfaceKey
	var vals []rfmRfmIfaceValue
	var keys []rfmRfmIfaceKey
	iter := p.objs.RfmIfaceStats.Iterate()
	for iter.Next(&key, &vals) {
		if drop(key.Ifindex) {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate iface stats: %w", err)
	}
	for _, k := range keys {
		if err := p.objs.RfmIfaceStats.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete iface stats %d: %w", k.Ifindex, err)
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
// the config map is read per skb, so the change applies at once without
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

// IfaceStatsErrors returns how many counter updates the programs could not
// store in the interface counter map, a full map is the usual cause, the
// traffic of a refused key goes uncounted
func (p *Probe) IfaceStatsErrors() (uint64, error) {
	var vals []uint64
	if err := p.objs.RfmIfaceErrors.Lookup(uint32(0), &vals); err != nil {
		return 0, fmt.Errorf("read iface stats errors: %w", err)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total, nil
}

// GSOHeaderErrors returns how many GSO skbs the programs counted without
// parsing their headers, an ingress one lacks the header bytes of its extra
// segments in the byte counters, and one without a segment count counts as a
// single packet
func (p *Probe) GSOHeaderErrors() (uint64, error) {
	var vals []uint64
	if err := p.objs.RfmGsoHdrErrors.Lookup(uint32(0), &vals); err != nil {
		return 0, fmt.Errorf("read gso header errors: %w", err)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total, nil
}

func (p *Probe) FlowEvents() *ebpf.Map {
	return p.objs.RfmFlowEvents
}

func (p *Probe) FlowDrops() *ebpf.Map {
	return p.objs.RfmFlowDrops
}

// Attach installs both programs on ifindex as TCX links, Watch attaches the
// matching links itself and only tests call Attach
// the ingress program is anchored at the head of the TCX chain and the egress
// program at its tail, so the counters see every frame the interface received
// before another program can drop or redirect it and every frame that is
// about to leave after other programs had their say, both counted as wire
// packets after segmentation, an egress frame before the qdisc, which may
// still drop it
// a link without an ethernet header is refused with ErrUnsupportedLink and a
// link that does not exist with an error matching unix.ENODEV
func (p *Probe) Attach(ifindex int) error {
	l, err := netlink.LinkByIndex(ifindex)
	if errors.As(err, new(netlink.LinkNotFoundError)) {
		return fmt.Errorf("look up link %d: %w", ifindex, unix.ENODEV)
	}
	if err != nil {
		return fmt.Errorf("look up link %d: %w", ifindex, err)
	}
	if err := checkLinkType(l.Attrs()); err != nil {
		return err
	}
	_, err = p.attach(ifindex, l.Attrs().Name)
	return err
}

// checkLinkType refuses a link whose frames do not start with an ethernet
// header at the tc hooks, loopback frames carry one as well
func checkLinkType(attrs *netlink.LinkAttrs) error {
	switch attrs.EncapType {
	case "ether", "loopback":
		return nil
	}
	return fmt.Errorf("link type %s: %w", attrs.EncapType, ErrUnsupportedLink)
}

// attach is Attach reporting whether the interface was newly attached, name
// is kept for the detach event
func (p *Probe) attach(ifindex int, name string) (bool, error) {
	p.mu.Lock()
	_, attached := p.links[ifindex]
	p.mu.Unlock()
	if attached {
		return false, nil
	}

	ing, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   p.objs.RfmTcIngress,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Head(),
	})
	if err != nil {
		return false, fmt.Errorf("attach ingress on %d: %w", ifindex, err)
	}

	egr, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   p.objs.RfmTcEgress,
		Attach:    ebpf.AttachTCXEgress,
		Anchor:    link.Tail(),
	})
	if err != nil {
		ing.Close()
		return false, fmt.Errorf("attach egress on %d: %w", ifindex, err)
	}

	p.mu.Lock()
	p.links[ifindex] = ifaceLinks{name: name, ingress: ing, egress: egr}
	delete(p.pending, ifindex)
	p.mu.Unlock()
	return true, nil
}
