package export

// IfaceStatsEntry is a single entry from the BPF iface stats map,
// already summed across CPUs.
type IfaceStatsEntry struct {
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	Packets uint64
	Bytes   uint64
}

// IfaceStatsSource provides aggregated per-interface statistics.
// The probe implements this on Linux; tests use a mock.
type IfaceStatsSource interface {
	IfaceStats() ([]IfaceStatsEntry, error)
}
