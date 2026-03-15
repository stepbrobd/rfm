//go:build !linux

package export

import "ysun.co/rfm/probe"

// ProbeSource adapts a *probe.Probe to the IfaceStatsSource interface.
// On non-Linux platforms, it always returns nil.
type ProbeSource struct {
	Probe *probe.Probe
}

// IfaceStats returns nil on non-Linux platforms.
func (s *ProbeSource) IfaceStats() []IfaceStatsEntry {
	return nil
}
