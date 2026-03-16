//go:build !linux

package export

import "ysun.co/rfm/probe"

// ProbeSource adapts a *probe.Probe to the IfaceStatsSource interface.
// On non-Linux platforms, it always returns nil.
type ProbeSource struct {
	Probe *probe.Probe
}

// IfaceStats returns nil on non-Linux platforms.
func (s *ProbeSource) IfaceStats() ([]IfaceStatsEntry, error) {
	return nil, nil
}

// SampleRate returns the default no-sampling rate on non-Linux platforms.
func (s *ProbeSource) SampleRate() (uint32, error) {
	return 1, nil
}
