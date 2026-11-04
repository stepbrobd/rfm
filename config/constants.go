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

// the defaults of the other settings a config leaves out, the readme documents each
const (
	// defaultSampleRate samples 1 in 100 skbs
	defaultSampleRate = 100
	// defaultRingBufSize is 256 KiB, a power of two and a whole number of pages
	defaultRingBufSize = 256 << 10
	// defaultWakeupBatch wakes the reader once every 1024 events of a slot entry, or of a cpu for an interface without a slot
	defaultWakeupBatch = 1024
	// maxIfaceSlots is RFM_SLOTS in bpf/rfm_common.h, the bound the programs check a slot against
	maxIfaceSlots = 256
	// defaultMaxSampleRate caps the adaptive and the set rate at 1 in 1000
	defaultMaxSampleRate = 1000
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
