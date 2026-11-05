package config

import "time"

// DefaultMaxFlows is the flow table size when max_flows is not set
const DefaultMaxFlows = 65536

// default exporter sizing
const (
	DefaultIPFIXQueueSize      = 4096
	DefaultIPFIXMaxMessageSize = 1200
)

// MinIPFIXMaxMessageSize holds the message header, the ipv6 template set and one ipv6 record
const MinIPFIXMaxMessageSize = 171

// maxStageEvents is RFM_STAGE_MAX in bpf/rfm_common.h, the events the stage of a cpu holds
const maxStageEvents = 32

// the defaults of the other settings a config leaves out, the readme documents each
const (
	// defaultSampleRate samples 1 in 100 skbs
	defaultSampleRate = 100
	// maxRingBufSize is the ring of each cpu at sample rate 1, which a one queue flood fills in about 3 ms without a reader
	maxRingBufSize = 256 << 10
	// minRingBufSize is the smallest ring a derived size goes down to, sample rates from 4 up share it, and its batch of 512 events keeps the wakeups of a busy cpu few
	minRingBufSize = 64 << 10
	// maxDerivedRingBufSize bounds the ring a large wakeup batch derives, a batch past it must set the ring
	maxDerivedRingBufSize = 64 << 20
	// maxSetRingBufSize is the largest ring the kernel takes, a power of two in its 32 bit size
	maxSetRingBufSize = 1 << 31
	// ringRecordBytes is one flow event of 56 bytes and the 8 byte header of its ring record
	ringRecordBytes = 64
	// maxIfaceSlots is RFM_SLOTS in bpf/rfm_common.h, the bound the programs check a slot against
	maxIfaceSlots = 256
	// defaultMaxSampleRate caps the adaptive and the set rate at 1 in 1000
	defaultMaxSampleRate = 1000
	// defaultStageEvents writes every event to the ring at once, which takes no flush timer and loads on PREEMPT_RT kernels too
	defaultStageEvents = 1
	// defaultEvictionTimeout ends a flow idle for 30 s
	defaultEvictionTimeout = 30 * time.Second
	// defaultActiveTimeout reports a busy flow once a minute
	defaultActiveTimeout = time.Minute
	// defaultTemplateRefresh lets a collector that lost a template or restarted recover within a minute
	defaultTemplateRefresh = time.Minute
	// defaultObservationDomainID is the first id, the config rejects 0
	defaultObservationDomainID = 1
	// defaultHost is loopback, for the host of an endpoint that names only its port
	defaultHost = "::1"
	// defaultIPFIXPort is the IANA port of IPFIX (RFC 7011)
	defaultIPFIXPort = 4739
	// defaultBMPPort is the BMP listen port when the config names only the host
	defaultBMPPort = 11019
	// defaultPrometheusPort is the metrics port when the config names none
	defaultPrometheusPort = 9669
)
