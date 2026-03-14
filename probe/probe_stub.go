//go:build !linux

package probe

import (
	"errors"

	"github.com/cilium/ebpf"
)

var errUnsupported = errors.New("probe is only supported on linux")

type Probe struct{}

func Load() (*Probe, error) {
	return nil, errUnsupported
}

func (p *Probe) Close() error {
	return nil
}

func (p *Probe) Config() *ebpf.Map {
	return nil
}

func (p *Probe) IfaceStats() *ebpf.Map {
	return nil
}

func (p *Probe) Attach(int) error {
	return errUnsupported
}
