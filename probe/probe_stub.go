//go:build !linux

package probe

import (
	"errors"

	"github.com/cilium/ebpf"
)

var errUnsupported = errors.New("probe is only supported on linux")

type Probe struct{}

func Load(Config) (*Probe, error) {
	return nil, errUnsupported
}

func (p *Probe) Close() error {
	return nil
}

func (p *Probe) Config() *ebpf.Map {
	return nil
}

func (p *Probe) SampleRate() (uint32, error) {
	return 0, errUnsupported
}

func (p *Probe) IfaceStats() *ebpf.Map {
	return nil
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
