package probe

// Config is what Load sets up, SetSampleRate changes the rate afterwards
type Config struct {
	SampleRate  uint32
	WakeupBatch uint32
	// RingBufSize is the size in bytes of the event ring of each possible
	// CPU, 0 keeps the 256 KiB of the object
	RingBufSize    int
	IfaceStatsSize int
	// SampledOnly loads the programs that keep no interface counters and leaves the pins alone
	SampledOnly bool
	// PinPath is a bpffs directory where the interface counters are pinned
	// so they survive a restart, empty keeps them private to the process
	PinPath string
}
