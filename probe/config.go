package probe

// Config holds all BPF program configuration
// the agent writes these values into BPF maps during startup, and the
// config map can be updated later without reloading the programs
type Config struct {
	SampleRate     uint32
	Flags          uint32
	WakeupBatch    uint32
	RingBufSize    int
	IfaceStatsSize int
	// PinPath is a bpffs directory where the interface counters are pinned
	// so they survive a restart, empty keeps them private to the process
	PinPath string
}
