//go:build linux

package export

import (
	"ysun.co/rfm/probe"
)

// ProbeSource adapts a *probe.Probe to the IfaceStatsSource interface
type ProbeSource struct {
	Probe *probe.Probe
}

// IfaceStats reads the probe's interface counters, summed over CPUs and over
// the counter slots and the hash
func (s *ProbeSource) IfaceStats() ([]IfaceStatsEntry, error) {
	counters, err := s.Probe.Counters()
	if err != nil {
		return nil, err
	}
	entries := make([]IfaceStatsEntry, len(counters))
	for i, c := range counters {
		entries[i] = IfaceStatsEntry{Ifindex: c.Ifindex, Dir: c.Dir, Proto: c.Proto, Packets: c.Packets, Bytes: c.Bytes}
	}
	return entries, nil
}

// IfaceStatsErrors reads how many counter updates the interface stats map
// refused
func (s *ProbeSource) IfaceStatsErrors() (uint64, error) {
	return s.Probe.IfaceStatsErrors()
}

// GSOHeaderErrors reads how many gso skbs were counted without the header size they needed
func (s *ProbeSource) GSOHeaderErrors() (uint64, error) {
	return s.Probe.GSOHeaderErrors()
}
