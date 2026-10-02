package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"sort"
	"strconv"
	"time"

	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
	"ysun.co/rfm/ctl"
	"ysun.co/rfm/enrich"
	"ysun.co/rfm/enrich/rib"
	"ysun.co/rfm/export"
)

// controlHandler answers control socket requests from the live agent state
type controlHandler struct {
	started  time.Time
	cfg      *config.Config
	cfgText  string
	probe    interface{ Attached() []int }
	col      *collector.Collector
	ipfix    *export.IPFIXExporter
	backends *enrich.Backends
	// interfaces lists the links of the host, net.Interfaces when nil
	interfaces func() ([]net.Interface, error)
}

// ifnames maps interface indexes to names, an index without a link shows as
// its number
type ifnames map[int]string

func (n ifnames) name(ifindex int) string {
	if name, ok := n[ifindex]; ok {
		return name
	}
	return strconv.Itoa(ifindex)
}

// linkNames resolves interface names for one request, every lookup of an index
// dumps all links over netlink, so a request lists them once instead, and
// fails when the dump does rather than show every interface as its number
func (h *controlHandler) linkNames() (ifnames, error) {
	list := h.interfaces
	if list == nil {
		list = net.Interfaces
	}
	links, err := list()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	names := make(ifnames, len(links))
	for _, l := range links {
		names[l.Index] = l.Name
	}
	return names, nil
}

func (h *controlHandler) Status() (ctl.Status, error) {
	bi, _ := debug.ReadBuildInfo()
	stats := h.col.Stats()

	st := ctl.Status{
		Version: resolveVersion(version, bi),
		Uptime:  time.Since(h.started).Round(time.Second),
		Sampling: ctl.Sampling{
			Rate:     h.col.SampleRate(),
			Base:     h.cfg.Agent.BPF.SampleRate,
			Max:      h.cfg.Agent.BPF.MaxSampleRate,
			Adaptive: h.cfg.Agent.BPF.AdaptiveSampling,
		},
		Flows: ctl.Flows{
			Active:          stats.ActiveFlows,
			Max:             h.cfg.Agent.Collector.MaxFlows,
			DroppedEvents:   stats.DroppedEvents,
			ForcedEvictions: stats.ForcedEvictions,
		},
	}

	if h.probe != nil {
		names, err := h.linkNames()
		if err != nil {
			return ctl.Status{}, err
		}
		for _, ifindex := range h.probe.Attached() {
			st.Interfaces = append(st.Interfaces, ctl.Interface{Name: names.name(ifindex), Ifindex: ifindex})
		}
		sort.Slice(st.Interfaces, func(i, j int) bool { return st.Interfaces[i].Ifindex < st.Interfaces[j].Ifindex })
	}

	if h.ipfix != nil {
		s := h.ipfix.Stats()
		st.IPFIX = &ctl.IPFIX{
			Collector:    h.cfg.Agent.IPFIX.Addr(),
			Connected:    s.Connected,
			Messages:     s.Messages,
			Records:      s.Records,
			QueueDropped: s.QueueDropped,
			Unsent:       s.Unsent,
			SendErrors:   s.SendErrors,
		}
	}

	if h.backends != nil && h.backends.MMDB != nil {
		asn, city := h.backends.MMDB.Versions()
		st.MMDB = &ctl.MMDB{ASNBuildEpoch: asn, CityBuildEpoch: city}
	}
	if h.backends != nil && h.backends.RIB != nil {
		summary, err := h.RIBSummary()
		if err != nil {
			return ctl.Status{}, err
		}
		st.RIB = &summary
	}
	return st, nil
}

// FlowsTop orders the live flows and builds rows for the first n only, so a
// table of tens of thousands of flows costs one sort and one link dump
func (h *controlHandler) FlowsTop(n int, by string) ([]ctl.FlowRow, error) {
	type flow struct {
		key   collector.FlowKey
		entry collector.FlowEntry
	}
	snapshot := h.col.Flows()
	flows := make([]flow, 0, len(snapshot))
	for key, entry := range snapshot {
		flows = append(flows, flow{key, entry})
	}
	sort.Slice(flows, func(i, j int) bool {
		a, b := flows[i].entry, flows[j].entry
		if by == "packets" {
			if a.EstPackets != b.EstPackets {
				return a.EstPackets > b.EstPackets
			}
		} else if a.EstBytes != b.EstBytes {
			return a.EstBytes > b.EstBytes
		}
		return a.FirstSeen.Before(b.FirstSeen)
	})
	flows = flows[:min(n, len(flows))]

	names, err := h.linkNames()
	if err != nil {
		return nil, err
	}
	rows := make([]ctl.FlowRow, len(flows))
	for i, f := range flows {
		key, entry := f.key, f.entry
		rows[i] = ctl.FlowRow{
			Interface:  names.name(int(key.Ifindex)),
			Direction:  direction(key.Dir),
			Proto:      key.Proto,
			Src:        key.SrcAddr.Unmap(),
			Dst:        key.DstAddr.Unmap(),
			SrcPort:    key.SrcPort,
			DstPort:    key.DstPort,
			SrcASN:     entry.Src.ASN,
			DstASN:     entry.Dst.ASN,
			SrcCity:    entry.Src.City,
			DstCity:    entry.Dst.City,
			Packets:    entry.Packets,
			Bytes:      entry.Bytes,
			EstPackets: entry.EstPackets,
			EstBytes:   entry.EstBytes,
			FirstSeen:  entry.FirstSeen,
			LastSeen:   entry.LastSeen,
		}
	}
	return rows, nil
}

func (h *controlHandler) FlowsCount() uint64 {
	return h.col.Stats().ActiveFlows
}

var errNoRIB = errors.New("rib not configured, set agent.enrich.rib.bmp")

func (h *controlHandler) RIBLookup(addr netip.Addr) (ctl.Route, bool, error) {
	if h.backends == nil || h.backends.RIB == nil {
		return ctl.Route{}, false, errNoRIB
	}
	route, ok := h.backends.RIB.Lookup(addr)
	if !ok {
		return ctl.Route{}, false, nil
	}
	return ctlRoute(route), true, nil
}

func (h *controlHandler) RIBSummary() (ctl.RIB, error) {
	if h.backends == nil || h.backends.RIB == nil {
		return ctl.RIB{}, errNoRIB
	}
	s := h.backends.RIB.Table().Summary()
	return ctl.RIB{
		Listen:     h.cfg.Agent.Enrich.RIB.BMP.Addr(),
		PrefixesV4: s.PrefixesV4,
		PrefixesV6: s.PrefixesV6,
		Routes:     s.Routes,
		Peers:      s.Peers,
	}, nil
}

// SetSampleRate checks rate against max_sample_rate and hands it to the
// collector, which writes the probe and records the rate for scaling in one
// step with the adaptive changes, adaptive sampling then moves on from rate
func (h *controlHandler) SetSampleRate(rate uint32) error {
	if limit := h.cfg.Agent.BPF.MaxSampleRate; rate > limit {
		return fmt.Errorf("rate %d above max_sample_rate %d", rate, limit)
	}
	return h.col.ApplySampleRate(rate)
}

func (h *controlHandler) ConfigShow() string {
	return h.cfgText
}

func (h *controlHandler) ReloadMMDB() error {
	if h.backends == nil || h.backends.MMDB == nil {
		return errors.New("mmdb not configured, set agent.enrich.mmdb")
	}
	return h.backends.MMDB.Reload()
}

func ctlRoute(r rib.Route) ctl.Route {
	out := ctl.Route{
		Prefix:      r.Prefix,
		OriginASN:   r.OriginASN,
		OriginASSet: r.OriginASSet,
		ASPath:      r.ASPath,
		PeerASN:     r.PeerASN,
		PeerAddress: r.PeerAddress,
		PostPolicy:  r.PostPolicy,
	}
	for _, c := range r.Communities {
		out.Communities = append(out.Communities, fmt.Sprintf("%d:%d", c>>16, c&0xffff))
	}
	for _, c := range r.LargeCommunities {
		out.LargeCommunities = append(out.LargeCommunities, fmt.Sprintf("%d:%d:%d", c.GlobalAdmin, c.LocalData1, c.LocalData2))
	}
	return out
}

func direction(dir uint8) string {
	if dir == 0 {
		return "ingress"
	}
	return "egress"
}
