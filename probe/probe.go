//go:build linux

package probe

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Probe holds loaded BPF objects and attached links
type Probe struct {
	objs  *rfmObjects
	links []link.Link
}

// Load loads the BPF objects into the kernel
func Load() (*Probe, error) {
	var objs rfmObjects
	if err := loadRfmObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF: %w", err)
	}
	return &Probe{objs: &objs}, nil
}

// Close detaches all links and closes BPF objects
func (p *Probe) Close() error {
	var errs []error
	for _, l := range p.links {
		errs = append(errs, l.Close())
	}
	errs = append(errs, p.objs.Close())
	return errors.Join(errs...)
}

// Config returns the config map for direct manipulation
func (p *Probe) Config() *ebpf.Map {
	return p.objs.RfmConfig
}

// IfaceStats returns the iface stats map
func (p *Probe) IfaceStats() *ebpf.Map {
	return p.objs.RfmIfaceStats
}

// Attach attaches TC ingress and egress programs to the given interface
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
