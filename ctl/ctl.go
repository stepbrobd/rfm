// Package ctl is the control plane between a running agent and the rfm
// command line, one JSON request and one JSON response per connection on a
// unix socket, the way birdc talks to bird
package ctl

import (
	"encoding/json"
	"net/netip"
	"time"
)

// Request is one command sent to the agent
type Request struct {
	Command string            `json:"command"`
	Args    map[string]string `json:"args,omitempty"`
}

// Response carries the command result or an error message
type Response struct {
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// command names
const (
	CmdStatus     = "status"
	CmdFlowsTop   = "flows.top"
	CmdFlowsCount = "flows.count"
	CmdRIBLookup  = "rib.lookup"
	CmdRIBSummary = "rib.summary"
	CmdSetRate    = "set.sample-rate"
	CmdConfigShow = "config.show"
	CmdReloadMMDB = "reload.mmdb"
)

// Status is what `rfm status` shows
type Status struct {
	Version    string        `json:"version"`
	Uptime     time.Duration `json:"uptime"`
	Interfaces []Interface   `json:"interfaces"`
	Sampling   Sampling      `json:"sampling"`
	Flows      Flows         `json:"flows"`
	IPFIX      *IPFIX        `json:"ipfix,omitempty"`
	MMDB       *MMDB         `json:"mmdb,omitempty"`
	RIB        *RIB          `json:"rib,omitempty"`
}

// Interface is one attached interface
type Interface struct {
	Name    string `json:"name"`
	Ifindex int    `json:"ifindex"`
}

// Sampling describes the sample rate in force
type Sampling struct {
	Rate     uint32 `json:"rate"`
	Base     uint32 `json:"base"`
	Max      uint32 `json:"max"`
	Adaptive bool   `json:"adaptive"`
}

// Flows describes the flow table
type Flows struct {
	Active          uint64 `json:"active"`
	Max             int    `json:"max"`
	DroppedEvents   uint64 `json:"dropped_events"`
	ForcedEvictions uint64 `json:"forced_evictions"`
	// Folded counts the flows counted under empty enrichment labels because
	// their label tuple found no room under the rollup cap
	Folded uint64 `json:"folded"`
}

// IPFIX describes the exporter
type IPFIX struct {
	Collector    string            `json:"collector"`
	Connected    bool              `json:"connected"`
	Messages     uint64            `json:"messages"`
	Records      uint64            `json:"records"`
	QueueDropped uint64            `json:"queue_dropped"`
	Unsent       uint64            `json:"unsent"`
	SendErrors   map[string]uint64 `json:"send_errors,omitempty"`
	// SendFailed counts the records lost with messages that failed to send
	SendFailed uint64 `json:"send_failed"`
}

// MMDB describes the loaded databases by build epoch
type MMDB struct {
	ASNBuildEpoch  uint `json:"asn_build_epoch"`
	CityBuildEpoch uint `json:"city_build_epoch"`
}

// RIB describes the BMP fed table
type RIB struct {
	Listen     string `json:"listen"`
	PrefixesV4 int    `json:"prefixes_v4"`
	PrefixesV6 int    `json:"prefixes_v6"`
	Routes     int    `json:"routes"`
	// Peers counts the views that hold routes, the pre and the post policy
	// table of a peer are two views
	Peers int `json:"peers"`
}

// FlowRow is one live flow as shown by `rfm flows top`
type FlowRow struct {
	Interface  string     `json:"interface"`
	Direction  string     `json:"direction"`
	Proto      uint8      `json:"proto"`
	Src        netip.Addr `json:"src"`
	Dst        netip.Addr `json:"dst"`
	SrcPort    uint16     `json:"src_port"`
	DstPort    uint16     `json:"dst_port"`
	SrcASN     uint32     `json:"src_asn,omitempty"`
	DstASN     uint32     `json:"dst_asn,omitempty"`
	SrcCity    string     `json:"src_city,omitempty"`
	DstCity    string     `json:"dst_city,omitempty"`
	Packets    uint64     `json:"packets"`
	Bytes      uint64     `json:"bytes"`
	EstPackets uint64     `json:"est_packets"`
	EstBytes   uint64     `json:"est_bytes"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
}

// Route is a RIB entry as shown by `rfm rib lookup`
type Route struct {
	Prefix           netip.Prefix `json:"prefix"`
	OriginASN        uint32       `json:"origin_asn"`
	OriginASSet      bool         `json:"origin_as_set,omitempty"`
	ASPath           []uint32     `json:"as_path"`
	Communities      []string     `json:"communities,omitempty"`
	LargeCommunities []string     `json:"large_communities,omitempty"`
	PeerASN          uint32       `json:"peer_asn"`
	PeerAddress      netip.Addr   `json:"peer_address"`
	PostPolicy       bool         `json:"post_policy"`
	// Truncated marks a route whose AS path, communities or large
	// communities were longer than the RIB keeps, they hold only their
	// leading values
	Truncated bool `json:"truncated,omitempty"`
}

// Handler answers control requests on behalf of the agent
type Handler interface {
	Status() (Status, error)
	// FlowsTop returns the n busiest live flows ordered by "bytes" or "packets"
	FlowsTop(n int, by string) ([]FlowRow, error)
	FlowsCount() uint64
	RIBLookup(addr netip.Addr) (Route, bool, error)
	RIBSummary() (RIB, error)
	SetSampleRate(rate uint32) error
	ConfigShow() string
	ReloadMMDB() error
}
