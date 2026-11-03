//go:build linux

package probe

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// ifaceLinks are the two tcx links of one attached interface
type ifaceLinks struct {
	name    string
	ingress link.Link
	egress  link.Link
}

type Probe struct {
	objs *rfmObjects
	// ingress and egress are the program pair Load loaded for the mode
	ingress, egress *ebpf.Program
	// rings holds the event ring of every possible CPU, by CPU
	rings []*ebpf.Map

	mu    sync.Mutex
	links map[int]ifaceLinks
	// skipped holds the matching links Watch left alone because of their
	// link type, so their warning is logged once
	skipped map[int]bool
	// pending holds the names of the matching links whose attach failed for
	// another reason than their removal, Watch tries them again
	pending map[int]string

	watchState WatchState

	// slots assigns the counter slots of rfm_iface_arr, guarded by mu
	slots *slotAlloc

	// rcvbuf overrides the receive buffer of the link subscription when
	// set, tests shrink it to make the socket overflow
	rcvbuf int
	// mangle, when set, sees the type and payload of every received link
	// message before the watcher reads them, tests corrupt one
	mangle func(typ uint16, data []byte)
}

func Load(cfg Config) (*Probe, error) {
	if cfg.SampleRate == 0 {
		return nil, errors.New("sample rate must be > 0")
	}
	if cfg.WakeupBatch == 0 {
		return nil, errors.New("wakeup batch must be > 0")
	}

	spec, err := loadRfm()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	// a ring per possible CPU, each of RingBufSize bytes
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("count CPUs: %w", err)
	}
	ringSpec := spec.Maps["rfm_flow_rings"].InnerMap.Copy()
	spec.Maps["rfm_flow_rings"].MaxEntries = uint32(ncpu)
	if cfg.RingBufSize > 0 {
		ringSpec.MaxEntries = uint32(cfg.RingBufSize)
	}

	if cfg.IfaceStatsSize > 0 {
		spec.Maps[pinStats].MaxEntries = uint32(cfg.IfaceStatsSize)
	}
	// sampled only keeps no counters, which also leaves no slot to assign
	if cfg.SampledOnly {
		for _, name := range []string{pinStats, pinSlot, pinArr} {
			spec.Maps[name].MaxEntries = 1
		}
	}

	// pinned counters carry over restarts, sampled only leaves them for the next exact load
	pin := cfg.PinPath != "" && !cfg.SampledOnly
	var opts ebpf.CollectionOptions
	var pinned map[string]*ebpf.Map
	if pin {
		pinned, err = loadPins(cfg.PinPath, spec)
		if err != nil {
			return nil, err
		}
		opts.MapReplacements = pinned
	}

	// only the program pair of the mode loads
	ingress, egress := "rfm_tc_ingress", "rfm_tc_egress"
	if cfg.SampledOnly {
		ingress, egress = "rfm_tc_ingress_sampled", "rfm_tc_egress_sampled"
	}
	p := &Probe{
		objs:    new(rfmObjects),
		rings:   make([]*ebpf.Map, 0, ncpu),
		links:   make(map[int]ifaceLinks),
		skipped: make(map[int]bool),
		pending: make(map[int]string),
		slots:   newSlotAlloc(int(spec.Maps[pinArr].MaxEntries)/(2*ifaceFamilies), spec.Maps[pinSlot].MaxEntries),
	}
	p.ingress, p.egress, err = loadObjects(spec, opts, p.objs, ingress, egress)
	// the collection holds its own handles now
	for _, m := range pinned {
		m.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("load BPF: %w", err)
	}
	if pin {
		for name, m := range map[string]*ebpf.Map{
			pinStats: p.objs.RfmIfaceStats,
			pinSlot:  p.objs.RfmIfaceSlot,
			pinArr:   p.objs.RfmIfaceArr,
		} {
			if pinned[name] != nil {
				continue
			}
			if err := m.Pin(filepath.Join(cfg.PinPath, name)); err != nil {
				p.Close()
				return nil, fmt.Errorf("pin %s: %w", name, err)
			}
		}
	}

	// a gen of its own redraws the skip counts a pinned counter array kept
	cfgVal := rfmRfmConfig{
		SampleRate:  cfg.SampleRate,
		WakeupBatch: cfg.WakeupBatch,
		Gen:         nextGen(rand.Uint32()),
	}
	if err := p.objs.RfmCfg.Set(cfgVal); err != nil {
		p.Close()
		return nil, fmt.Errorf("write config: %w", err)
	}

	for cpu := range ncpu {
		ring, err := ebpf.NewMap(ringSpec)
		if err == nil {
			p.rings = append(p.rings, ring)
			err = p.objs.RfmFlowRings.Put(uint32(cpu), ring)
		}
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("event ring of cpu %d: %w", cpu, err)
		}
	}

	if pinned[pinSlot] != nil {
		if err := p.restoreSlots(); err != nil {
			p.Close()
			return nil, err
		}
	}
	return p, nil
}

// loadObjects loads the maps and variables of spec into objs and returns the programs named ingress and egress
func loadObjects(spec *ebpf.CollectionSpec, opts ebpf.CollectionOptions, objs *rfmObjects, ingress, egress string) (*ebpf.Program, *ebpf.Program, error) {
	for name := range spec.Programs {
		if name != ingress && name != egress {
			delete(spec.Programs, name)
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, nil, err
	}
	defer coll.Close()
	if err := coll.Assign(&objs.rfmMaps); err != nil {
		return nil, nil, err
	}
	if err := coll.Assign(&objs.rfmVariables); err != nil {
		objs.rfmMaps.Close()
		return nil, nil, err
	}
	return coll.DetachProgram(ingress), coll.DetachProgram(egress), nil
}

// the pinned counter maps, the hash and the slot map with its counter array
const (
	pinStats = "rfm_iface_stats"
	pinSlot  = "rfm_iface_slot"
	pinArr   = "rfm_iface_arr"
)

// loadPins returns the counter maps pinned under dir by name, without the
// ones not pinned yet
// a pin the loader would refuse is an error that names the difference, the
// pin stays with its counters until it is removed or the host reboots
// the slot map and the counter array only make sense together, one pinned
// without the other is left from a start that stopped between the two pins,
// and both start from zero
func loadPins(dir string, spec *ebpf.CollectionSpec) (map[string]*ebpf.Map, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create pin directory %q: %w", dir, err)
	}

	pins := make(map[string]*ebpf.Map)
	closeAll := func() {
		for _, m := range pins {
			m.Close()
		}
	}
	for _, name := range []string{pinStats, pinSlot, pinArr} {
		path := filepath.Join(dir, name)
		m, err := ebpf.LoadPinnedMap(path, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("load pinned %s %q: %w", name, path, err)
		}
		// the same check the loader runs on a replacement map
		if err := spec.Maps[name].Compatible(m); err != nil {
			m.Close()
			closeAll()
			return nil, fmt.Errorf("pinned %s %q do not match the configured map, remove the pin file or reboot to start the counters from zero: %w", name, path, err)
		}
		pins[name] = m
	}

	if (pins[pinSlot] == nil) != (pins[pinArr] == nil) {
		for _, name := range []string{pinSlot, pinArr} {
			if m := pins[name]; m != nil {
				m.Close()
				delete(pins, name)
			}
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				closeAll()
				return nil, fmt.Errorf("remove the lone pin %s: %w", name, err)
			}
		}
		log.Warn("dropped a slot map or counter array pinned without the other, the slotted counters start from zero", "dir", dir)
	}
	return pins, nil
}

// restoreSlots reads back the slots an earlier run assigned from the pinned
// slot map, an entry the allocator refuses is cleared and its interface
// counts from zero in a new slot or the hash
func (p *Probe) restoreSlots() error {
	var ifindex, slot uint32
	var stale []uint32
	iter := p.objs.RfmIfaceSlot.Iterate()
	for iter.Next(&ifindex, &slot) {
		if slot == 0 {
			continue
		}
		if !p.slots.restore(ifindex, int(slot)-1) {
			stale = append(stale, ifindex)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("read pinned slot map: %w", err)
	}
	for _, i := range stale {
		if err := p.objs.RfmIfaceSlot.Put(i, uint32(0)); err != nil {
			return fmt.Errorf("clear stale slot of %d: %w", i, err)
		}
	}
	return nil
}

// assignSlot gives ifindex a counter slot, a fresh one with its counters
// zeroed before the programs can see it, and leaves it on the hash when no
// slot is free or ifindex is out of range
func (p *Probe) assignSlot(ifindex int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	slot, fresh, ok := p.slots.assign(uint32(ifindex))
	if !ok || !fresh {
		return nil
	}
	if err := p.zeroSlot(slot); err != nil {
		p.slots.release(uint32(ifindex))
		return err
	}
	if err := p.objs.RfmIfaceSlot.Put(uint32(ifindex), uint32(slot+1)); err != nil {
		p.slots.release(uint32(ifindex))
		return fmt.Errorf("publish slot of %d: %w", ifindex, err)
	}
	return nil
}

// releaseSlot takes the slot from ifindex and zeroes its counters, the
// caller holds mu
func (p *Probe) releaseSlot(ifindex uint32) error {
	slot, ok := p.slots.release(ifindex)
	if !ok {
		return nil
	}
	if err := p.objs.RfmIfaceSlot.Put(ifindex, uint32(0)); err != nil {
		return fmt.Errorf("unpublish slot of %d: %w", ifindex, err)
	}
	return p.zeroSlot(slot)
}

// zeroSlot clears every CPU's counters of slot
func (p *Probe) zeroSlot(slot int) error {
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("count CPUs: %w", err)
	}
	zero := make([]rfmRfmSlotValue, ncpu)
	for dir := range uint8(2) {
		for fam := range ifaceFamilies {
			if err := p.objs.RfmIfaceArr.Put(slotIndex(slot, dir, fam), zero); err != nil {
				return fmt.Errorf("zero counter slot %d: %w", slot, err)
			}
		}
	}
	return nil
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
	for _, ring := range p.rings {
		errs = append(errs, ring.Close())
	}
	errs = append(errs, p.objs.Close(), p.ingress.Close(), p.egress.Close())
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

// detach removes the programs from ifindex and drops its counters, reporting its attach name and whether it was attached
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

// clearIfaceStats frees the counter slot of ifindex and deletes its hash
// entries
func (p *Probe) clearIfaceStats(ifindex int) error {
	p.mu.Lock()
	err := p.releaseSlot(uint32(ifindex))
	p.mu.Unlock()
	return errors.Join(err, p.deleteIfaceStats(func(i uint32) bool { return i == uint32(ifindex) }))
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
	var errs []error
	for ifindex := range p.slots.held() {
		if !keep[ifindex] {
			errs = append(errs, p.releaseSlot(ifindex))
		}
	}
	p.mu.Unlock()
	errs = append(errs, p.deleteIfaceStats(func(i uint32) bool { return !keep[i] }))
	return errors.Join(errs...)
}

// deleteIfaceStats deletes the counter entries whose ifindex drop accepts
func (p *Probe) deleteIfaceStats(drop func(ifindex uint32) bool) error {
	var key rfmRfmIfaceKey
	var keys []rfmRfmIfaceKey
	err := p.objs.RfmIfaceStats.NextKey(nil, &key)
	for ; err == nil; err = p.objs.RfmIfaceStats.NextKey(key, &key) {
		if drop(key.Ifindex) {
			keys = append(keys, key)
		}
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
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
	var cfg rfmRfmConfig
	if err := p.objs.RfmCfg.Get(&cfg); err != nil {
		return 0, fmt.Errorf("read config: %w", err)
	}
	return cfg.SampleRate, nil
}

// SetSampleRate changes the 1-in-N sampling of the running programs
// the config is read per skb, so the change applies at once without
// detaching or reloading anything
func (p *Probe) SetSampleRate(n uint32) error {
	if n == 0 {
		return fmt.Errorf("sample rate must be > 0")
	}
	var cfg rfmRfmConfig
	if err := p.objs.RfmCfg.Get(&cfg); err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	cfg.SampleRate = n
	cfg.Gen = nextGen(cfg.Gen)
	if err := p.objs.RfmCfg.Set(cfg); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// nextGen is the config gen after gen, never 0, the gen of a zeroed slot
func nextGen(gen uint32) uint32 {
	if gen++; gen == 0 {
		gen = 1
	}
	return gen
}

// Counters sums CPUs and the slot and hash entries per interface, direction and family, leaving out empty ones
func (p *Probe) Counters() ([]IfaceCounter, error) {
	type key struct {
		ifindex    uint32
		dir, proto uint8
	}
	sums := make(map[key]IfaceCounter)

	// a walk that overlaps a delete restarts and can see a key twice, the later read wins
	var hk rfmRfmIfaceKey
	var vals []rfmRfmIfaceValue
	iter := p.objs.RfmIfaceStats.Iterate()
	for iter.Next(&hk, &vals) {
		c := IfaceCounter{Ifindex: hk.Ifindex, Dir: hk.Dir, Proto: hk.Proto}
		for _, v := range vals {
			c.Packets += v.Packets
			c.Bytes += v.Bytes
		}
		sums[key{hk.Ifindex, hk.Dir, hk.Proto}] = c
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate iface stats: %w", err)
	}

	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("count CPUs: %w", err)
	}
	// the slots keep their owners while mu is held
	p.mu.Lock()
	held := p.slots.held()
	n := 0
	for _, slot := range held {
		n = max(n, int(slotIndex(slot+1, 0, 0)))
	}
	svals := make([]rfmRfmSlotValue, n*ncpu)
	if n > 0 {
		var cursor ebpf.MapBatchCursor
		_, err := p.objs.RfmIfaceArr.BatchLookup(&cursor, make([]uint32, n), svals, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			p.mu.Unlock()
			return nil, fmt.Errorf("read counter slots: %w", err)
		}
	}
	p.mu.Unlock()
	for ifindex, slot := range held {
		for dir := range uint8(2) {
			for fam := range ifaceFamilies {
				i := int(slotIndex(slot, dir, fam))
				k := key{ifindex, dir, familyProto(fam)}
				c := sums[k]
				c.Ifindex, c.Dir, c.Proto = k.ifindex, k.dir, k.proto
				for _, v := range svals[i*ncpu : (i+1)*ncpu] {
					c.Packets += v.Packets
					c.Bytes += v.Bytes
				}
				sums[k] = c
			}
		}
	}

	out := make([]IfaceCounter, 0, len(sums))
	for _, c := range sums {
		if c.Packets != 0 || c.Bytes != 0 {
			out = append(out, c)
		}
	}
	return out, nil
}

// IfaceStatsErrors counts the counter updates rfm_iface_stats refused
func (p *Probe) IfaceStatsErrors() (uint64, error) {
	return sumCPUs(p.objs.RfmIfaceErrors)
}

// GSOHeaderErrors counts the gso skbs counted without the header size they needed
func (p *Probe) GSOHeaderErrors() (uint64, error) {
	return sumCPUs(p.objs.RfmGsoHdrErrors)
}

// sumCPUs sums the per-CPU values of the one entry of m
func sumCPUs(m *ebpf.Map) (uint64, error) {
	var vals []uint64
	if err := m.Lookup(uint32(0), &vals); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total, nil
}

// FlowRings returns the event ring of every possible CPU, by CPU
func (p *Probe) FlowRings() []*ebpf.Map {
	return p.rings
}

func (p *Probe) FlowDrops() *ebpf.Map {
	return p.objs.RfmFlowDrops
}

// checkLinkType refuses a link without an ethernet header at the tc hooks
func checkLinkType(attrs *netlink.LinkAttrs) error {
	switch attrs.EncapType {
	case "ether", "loopback":
		return nil
	}
	return fmt.Errorf("link type %s: %w", attrs.EncapType, errUnsupportedLink)
}

// attach installs both programs on ifindex, keeps name for the detach event and reports whether it newly attached them
func (p *Probe) attach(ifindex int, name string) (bool, error) {
	p.mu.Lock()
	_, attached := p.links[ifindex]
	p.mu.Unlock()
	if attached {
		return false, nil
	}

	// the slot is in place before the first packet, a pending link keeps it
	if err := p.assignSlot(ifindex); err != nil {
		return false, err
	}

	// rfm runs first on the ingress tcx chain and last on the egress one
	ing, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   p.ingress,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Head(),
	})
	if err != nil {
		return false, fmt.Errorf("attach ingress on %d: %w", ifindex, err)
	}

	egr, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   p.egress,
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
