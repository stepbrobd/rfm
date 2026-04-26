//go:build !linux

package collector

import (
	"errors"

	"github.com/cilium/ebpf"
)

var errUnsupported = errors.New("collector reader is only supported on linux")

// NewReader is not supported on non-Linux platforms
func NewReader(events, drops *ebpf.Map) (Reader, error) {
	return nil, errUnsupported
}
