package probe

// Config is what Load sets up, SetSampleRate changes the rate afterwards
type Config struct {
	SampleRate  uint32
	WakeupBatch uint32
	// RingBufSize is the size in bytes of the event ring of each online
	// CPU, 0 keeps the 256 KiB of the object
	RingBufSize int
	// IfaceStatsSize is the capacity of the counter hash, 0 keeps the 4096 of
	// the object or the capacity of a pinned hash
	IfaceStatsSize int
	// IfaceSlots is the counter slots of the per cpu array, 0 keeps
	// DefaultIfaceSlots or the slots of a pinned array
	IfaceSlots int
	// SampledOnly loads the programs that keep no interface counters and leaves the pins alone
	SampledOnly bool
	// StageEvents is how many sampled events a CPU stages before it writes
	// them to its ring as one record, 0 and 1 write every event at once,
	// more needs bpf_timer_start to take BPF_F_TIMER_CPU_PIN, Linux 6.7 or
	// later without PREEMPT_RT
	StageEvents uint32
	// PinPath is a bpffs directory where the interface counters are pinned
	// so they survive a restart, empty keeps them private to the process
	PinPath string
}
