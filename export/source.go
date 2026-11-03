package export

// IfaceStatsEntry is the traffic of one interface, direction and family, summed over CPUs and over its counter slot and hash entries
type IfaceStatsEntry struct {
	Ifindex uint32
	Dir     uint8
	Proto   uint8
	Packets uint64
	Bytes   uint64
}

// IfaceStatsSource provides the interface counters, ProbeSource reads them from the probe
type IfaceStatsSource interface {
	IfaceStats() ([]IfaceStatsEntry, error)
}

// IfaceStatsErrorSource provides how many counter updates the interface
// stats map refused, whose traffic went uncounted
type IfaceStatsErrorSource interface {
	IfaceStatsErrors() (uint64, error)
}

// GSOHeaderErrorSource provides how many gso skbs the programs counted without the header size they needed
type GSOHeaderErrorSource interface {
	GSOHeaderErrors() (uint64, error)
}
