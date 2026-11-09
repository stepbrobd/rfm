//go:build !linux

package probe

import (
	"context"
	"errors"
	"time"

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

func (p *Probe) SampleRate() (uint32, error) {
	return 0, errUnsupported
}

func (p *Probe) Counters() ([]IfaceCounter, error) {
	return nil, errUnsupported
}

func (p *Probe) IfaceStatsErrors() (uint64, error) {
	return 0, errUnsupported
}

func (p *Probe) GSOHeaderErrors() (uint64, error) {
	return 0, errUnsupported
}

func (p *Probe) FlowRings() []*ebpf.Map {
	return nil
}

func (p *Probe) FlowDrops() *ebpf.Map {
	return nil
}

func (p *Probe) WatchCPUs(context.Context, time.Duration, func(*ebpf.Map) error) {}

func (p *Probe) Attached() []int {
	return nil
}

func (p *Probe) Pending() []int {
	return nil
}

func (p *Probe) SetSampleRate(uint32) error {
	return errUnsupported
}

func (p *Probe) Watch(context.Context, func(string) bool, func(LinkEvent)) error {
	return errUnsupported
}

func (p *Probe) WatchState() WatchState {
	return WatchState{}
}

func (p *Probe) Synced() <-chan struct{} {
	return nil
}
