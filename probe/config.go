package probe

// Config holds all BPF program configuration
// the agent writes these values into BPF maps during startup, and the
// config map can be updated later without reloading the programs
type Config struct {
	SampleRate     uint32
	Flags          uint32
	RingBufSize    int
	IfaceStatsSize int
}
