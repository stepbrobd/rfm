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
	"ysun.co/rfm/probe"
)

// controlHandler answers control socket requests from the live agent state
type controlHandler struct {
	started  time.Time
	cfg      *config.Config
	cfgText  string
	probe    *probe.Probe
	col      *collector.Collector
	ipfix    *export.IPFIXExporter
	backends *enrich.Backends
}

func (h *controlHandler) Status() ctl.Status {
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
		for _, ifindex := range h.probe.Attached() {
			st.Interfaces = append(st.Interfaces, ctl.Interface{Name: ifname(ifindex), Ifindex: ifindex})
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
		summary, _ := h.RIBSummary()
		st.RIB = &summary
	}
	return st
}

func (h *controlHandler) FlowsTop(n int, by string) []ctl.FlowRow {
	flows := h.col.Flows()
	rows := make([]ctl.FlowRow, 0, len(flows))
	for key, entry := range flows {
		rows = append(rows, ctl.FlowRow{
			Interface:  ifname(int(key.Ifindex)),
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
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if by == "packets" {
			if rows[i].EstPackets != rows[j].EstPackets {
				return rows[i].EstPackets > rows[j].EstPackets
			}
		} else if rows[i].EstBytes != rows[j].EstBytes {
			return rows[i].EstBytes > rows[j].EstBytes
		}
		return rows[i].FirstSeen.Before(rows[j].FirstSeen)
	})
	if n < len(rows) {
		rows = rows[:n]
	}
	return rows
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

// SetSampleRate changes the rate in the probe and records it for scaling
// with adaptive sampling on, the controller may move it again later
func (h *controlHandler) SetSampleRate(rate uint32) error {
	if h.probe == nil {
		return errors.New("probe not loaded")
	}
	if err := h.probe.SetSampleRate(rate); err != nil {
		return err
	}
	h.col.SetSampleRateNow(rate)
	return nil
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

func ifname(ifindex int) string {
	iface, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return strconv.Itoa(ifindex)
	}
	return iface.Name
}

func direction(dir uint8) string {
	if dir == 0 {
		return "ingress"
	}
	return "egress"
}
