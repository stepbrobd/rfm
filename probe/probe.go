//go:build linux

package probe

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Probe struct {
	objs  *rfmObjects
	links []link.Link
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

	var objs rfmObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF: %w", err)
	}

	// write config into BPF map at load time
	cfgKey := uint32(0)
	cfgVal := rfmRfmConfig{
		SampleRate: cfg.SampleRate,
		Flags:      cfg.Flags,
	}
	if err := objs.RfmConfig.Update(cfgKey, cfgVal, ebpf.UpdateAny); err != nil {
		objs.Close()
		return nil, fmt.Errorf("write config: %w", err)
	}

	return &Probe{objs: &objs}, nil
}

func (p *Probe) Close() error {
	var errs []error
	for _, l := range p.links {
		errs = append(errs, l.Close())
	}
	errs = append(errs, p.objs.Close())
	return errors.Join(errs...)
}

func (p *Probe) SampleRate() (uint32, error) {
	key := uint32(0)
	var cfg rfmRfmConfig
	if err := p.objs.RfmConfig.Lookup(key, &cfg); err != nil {
		return 0, fmt.Errorf("read config: %w", err)
	}
	return cfg.SampleRate, nil
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

func (p *Probe) Attach(ifindex int) error {
	ing, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   p.objs.RfmTcIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach ingress on %d: %w", ifindex, err)
	}

	egr, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   p.objs.RfmTcEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		ing.Close()
		return fmt.Errorf("attach egress on %d: %w", ifindex, err)
	}

	p.links = append(p.links, ing, egr)
	return nil
}
