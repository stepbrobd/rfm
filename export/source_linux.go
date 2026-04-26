//go:build linux

package export

import (
	"fmt"
	"structs"

	"ysun.co/rfm/probe"
)

// ifaceKey mirrors the BPF rfm_iface_key struct for decoding map entries
type ifaceKey struct {
	_       structs.HostLayout
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	Pad     uint16
}

// ifaceValue mirrors the BPF rfm_iface_value struct for decoding map entries
type ifaceValue struct {
	_       structs.HostLayout
	Packets uint64
	Bytes   uint64
}

// ProbeSource adapts a *probe.Probe to the IfaceStatsSource interface
// by iterating the BPF per-CPU hash map
type ProbeSource struct {
	Probe *probe.Probe
}

// IfaceStats reads the BPF iface stats map, summing per-CPU values
func (s *ProbeSource) IfaceStats() ([]IfaceStatsEntry, error) {
	m := s.Probe.IfaceStats()
	if m == nil {
		return nil, nil
	}

	var entries []IfaceStatsEntry
	var key ifaceKey
	var vals []ifaceValue
	iter := m.Iterate()
	for iter.Next(&key, &vals) {
		var packets, bytes uint64
		for _, v := range vals {
			packets += v.Packets
			bytes += v.Bytes
		}
		entries = append(entries, IfaceStatsEntry{
			Ifindex: key.Ifindex,
			Dir:     key.Dir,
			Proto:   key.Proto,
			Packets: packets,
			Bytes:   bytes,
		})
	}
	if err := iter.Err(); err != nil {
		return entries, fmt.Errorf("iterate iface stats: %w", err)
	}
	return entries, nil
}

// SampleRate reads the current sample rate from the probe config map
func (s *ProbeSource) SampleRate() (uint32, error) {
	if s.Probe == nil {
		return 1, nil
	}
	rate, err := s.Probe.SampleRate()
	if err != nil {
		return 0, err
	}
	if rate == 0 {
		return 1, nil
	}
	return rate, nil
}
