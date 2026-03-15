package probe

// Config holds all BPF program configuration. All fields are written
// into BPF maps at load time. Any config change requires a full
// unload/reload cycle.
type Config struct {
	SampleRate     uint32
	Flags          uint32
	RingBufSize    int
	IfaceStatsSize int
}
