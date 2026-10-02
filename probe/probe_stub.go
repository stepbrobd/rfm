//go:build !linux

package probe

import (
	"context"
	"errors"

	"github.com/cilium/ebpf"
)

// LinkEvent is one attach or detach done by Watch
type LinkEvent struct {
	Name     string
	Ifindex  int
	Attached bool
}

var errUnsupported = errors.New("probe is only supported on linux")

type Probe struct{}

func Load(Config) (*Probe, error) {
	return nil, errUnsupported
}

func (p *Probe) Close() error {
	return nil
}

func (p *Probe) SampleRate() (uint32, error) {
	return 0, errUnsupported
}

func (p *Probe) IfaceStats() *ebpf.Map {
	return nil
}

func (p *Probe) IfaceStatsErrors() (uint64, error) {
	return 0, errUnsupported
}

func (p *Probe) FlowEvents() *ebpf.Map {
	return nil
}

func (p *Probe) FlowDrops() *ebpf.Map {
	return nil
}

func (p *Probe) Attach(int) error {
	return errUnsupported
}

func (p *Probe) Detach(int) error {
	return errUnsupported
}

func (p *Probe) Attached() []int {
	return nil
}

func (p *Probe) SetSampleRate(uint32) error {
	return errUnsupported
}

func (p *Probe) Watch(context.Context, func(string) bool, func(LinkEvent)) error {
	return errUnsupported
}
