package export

// IfaceStatsEntry is a single entry from the BPF iface stats map,
// already summed across CPUs
type IfaceStatsEntry struct {
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	Packets uint64
	Bytes   uint64
}

// IfaceStatsSource provides aggregated per-interface statistics
// the probe implements this on Linux, tests use a mock
type IfaceStatsSource interface {
	IfaceStats() ([]IfaceStatsEntry, error)
}

// SampleRateSource provides the current packet sample rate used by the probe
type SampleRateSource interface {
	SampleRate() (uint32, error)
}

// IfaceStatsErrorSource provides how many counter updates the interface
// stats map refused, whose traffic went uncounted
type IfaceStatsErrorSource interface {
	IfaceStatsErrors() (uint64, error)
}

// GSOHeaderErrorSource provides how many GSO skbs the programs counted
// without parsing their headers, an ingress one lacks the header bytes of its
// extra segments and one without a segment count counts as one packet
type GSOHeaderErrorSource interface {
	GSOHeaderErrors() (uint64, error)
}
