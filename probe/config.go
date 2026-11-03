package probe

// Config is what Load sets up, SetSampleRate changes the rate afterwards
type Config struct {
	SampleRate  uint32
	WakeupBatch uint32
	// RingBufSize is the size in bytes of the event ring of each possible
	// CPU, 0 keeps the 256 KiB of the object
	RingBufSize    int
	IfaceStatsSize int
	// SampledOnly keeps no interface counters, the programs draw before
	// anything else and a packet they pass over costs only the draw, and
	// the pins under PinPath stay as they are for the next exact load
	SampledOnly bool
	// PinPath is a bpffs directory where the interface counters are pinned
	// so they survive a restart, empty keeps them private to the process
	PinPath string
}
