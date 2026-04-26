# RFM

RFM (Router Flow Monitor) is an eBPF-based network flow analysis agent for Linux
routers. It attaches TC programs to network interfaces, collects per-flow
traffic statistics with configurable sampling, optionally enriches flows from a
live BMP-fed RIB and/or MMDB ASN/city databases, and exports the results to
Prometheus and IPFIX.

Requirements:

- Linux 6.12 or newer (TCX, `bpf_ktime_get_boot_ns`)
- Go 1.25+
- Root or `CAP_BPF` + `CAP_NET_ADMIN`

Current scope:

- Attaches TC programs for bidirectional flow observation
- Parses ipv4 and ipv6 traffic on plain ethernet, VLAN, and QinQ links
- Keeps BPF behavior fully map-driven and stateless
- Optionally enriches flows in userspace with BMP/RIB data, MMDB data, or both
- Exports Prometheus metrics
- Optionally exports completed flows to one UDP IPFIX collector
- Ships a typed NixOS module and VM coverage

Planned:

- Unix socket control plane
- XDP firewall fast-path features

rfm runs as a single daemon (`rfm agent`) that loads eBPF programs, collects
flow events in userspace, and serves Prometheus metrics over HTTP.

```
+------------------------------------+
|            kernel                  |
|  TC ingress --+                    |
|               +---> ring buffer -----> userspace collector
|  TC egress  --+                    |
|                                    |
|  per-CPU iface stats map ------------> Prometheus /metrics
+------------------------------------+
```

BPF programs are attached via TCX as link-based attachments. BPF behavior is
map-driven: sampling rates and feature flags live in a shared `rfm_config` map
rather than compiled-in constants. The config map is writable at runtime, though
the current agent writes it during startup.

### Data path

1. TC programs classify each packet by direction, protocol family, and 5-tuple
   after ethernet, VLAN, and QinQ parsing. Every packet updates per-CPU
   interface counters. Sampled packets (1-in-N) emit a flow event to a ring
   buffer. IPv4 non-initial fragments keep the IP protocol but export
   `src_port=0` and `dst_port=0` because later fragments do not carry the
   transport header.
2. The userspace collector reads events from the ring buffer, converts
   `CLOCK_BOOTTIME` timestamps to wall clock time, and aggregates flows into an
   in-memory table keyed by
   `(ifindex, direction, protocol,
   src/dst address, src/dst port)`.
3. Flows are evicted after a configurable idle timeout. When the flow table is
   full, the flow with the oldest last-seen timestamp is forcibly evicted.
4. At scrape time, the Prometheus exporter reads the BPF interface counters map
   directly and iterates the flow table, rolling up flows by interface,
   direction, protocol, and enrichment labels (ASN, city) before emitting
   metrics. With no enrichment configured, those labels stay empty and the agent
   still runs normally.
5. When IPFIX is enabled, completed flows are exported on eviction and agent
   shutdown. The exporter owns its UDP socket and excludes only that exact
   socket tuple from recursive self-export.

## Configuration

rfm reads a TOML config file (default `/etc/rfm/rfm.toml`). Unknown keys are
rejected at load time to catch typos. Example:

```toml
[agent]
interfaces = ["eth0", "tailscale0"]

[agent.bpf]
sample_rate = 100
ring_buf_size = 262144
wakeup_batch = 64

[agent.collector]
max_flows = 65536
eviction_timeout = "30s"

[agent.ipfix]
host = "127.0.0.1"
port = 4739
template_refresh = "60s"
observation_domain_id = 1

[agent.ipfix.bind]
host = "192.0.2.10"
port = 0

[agent.prometheus]
host = "::1"
port = 9669

[agent.enrich.mmdb]
asn_db = "/var/lib/rfm/dbip-asn-lite.mmdb"
city_db = "/var/lib/rfm/dbip-city-lite.mmdb"

[agent.enrich.rib.bmp]
host = "127.0.0.1"
port = 11019
```

### `agent`

`interfaces` (required, list of strings): Network interfaces to attach BPF
programs to. Each entry must be a valid interface name present on the system.
Duplicates are rejected. Set to `["*"]` to monitor all non-loopback interfaces.
The wildcard cannot be mixed with named interfaces.

### `agent.bpf`

`sample_rate` (uint32, default 100): Sample 1 in every N packets for flow
events. Must be greater than 0. A value of 1 samples every packet. Higher values
reduce ring buffer throughput at the cost of flow granularity.

`ring_buf_size` (int, default 262144): Size of the BPF ring buffer in bytes.
Must be greater than 0 and a power of two. Invalid values are rejected at config
load time. Larger buffers reduce the chance of dropped events under burst
traffic.

`wakeup_batch` (uint32, default 64): The BPF program flags ring buffer submits
with `BPF_RB_NO_WAKEUP` and forces a wakeup once every N submits. Lower values
reduce flow event delivery latency at the cost of more userspace wakeups; higher
values amortize wakeups but make Run loop iterations slower to react. Must be
greater than 0.

`iface_stats_size` (int, default 0): Override the BPF iface stats hash map
capacity. `0` means auto-compute as `max(len(interfaces) * 8, 64)`. Set
explicitly when running on a router with many subinterfaces or known high
cardinality where the auto-compute is too small.

### `agent.collector`

`max_flows` (int, default 65536): Maximum number of active flows held in memory.
Must be >= 0. When the table is full, the oldest flow is forcibly evicted. A
value of 0 means unlimited.

`eviction_timeout` (string, default "30s"): How long a flow can be idle before
eviction. Accepts any Go duration string (e.g. "10s", "1m", "2s"). Minimum value
is 1s.

### `agent.ipfix`

`host` (string, default ""): Collector host for UDP IPFIX export. If
`agent.ipfix.host` and `agent.ipfix.port` are both unset, IPFIX export stays
disabled.

`port` (int, default 0): Collector UDP port for IPFIX export. If only one IPFIX
field is set, the other defaults to `::1` or `4739`.

`bind.host` (string, default ""): Local source address for the exporter UDP
socket. When unset, the kernel picks the source address from routing.

`bind.port` (int, default 0): Local source port for the exporter UDP socket. `0`
keeps the current behavior and uses an ephemeral port chosen by the kernel.

`template_refresh` (string, default "60s"): How often UDP IPFIX templates are
re-sent. Accepts any Go duration string. Minimum 1s. RFC 7011 requires UDP
exporters to re-send templates regularly because the transport is lossy. The
default of 60s lets a collector that loses or restarts during a packet recover
within one refresh window.

`observation_domain_id` (uint32, default 1): IPFIX observation domain id placed
in exported message headers. Must be > 0. Set distinct values when multiple rfm
agents export to one collector and downstream needs to demultiplex by source.

### `agent.prometheus`

`host` (string, default "::1"): Address to bind the Prometheus metrics HTTP
server to. Use "::1" to restrict to local IPv6 loopback, "127.0.0.1" for local
IPv4 only, "::" for all interfaces, or "0.0.0.0" for all IPv4 interfaces.

`port` (int, default 9669): TCP port for the metrics server. Must be between 1
and 65535.

### `agent.enrich`

All enrichment backends are optional. If `agent.enrich` is omitted, the agent
still starts and `src_asn`, `dst_asn`, `src_city`, and `dst_city` stay empty.

`mmdb.asn_db` (string, default ""): Path to an ASN MMDB database. Startup fails
early if the configured path is missing or unreadable.

`mmdb.city_db` (string, default ""): Path to a city MMDB database. Startup fails
early if the configured path is missing or unreadable.

`rib.bmp.host` (string, default ""): BMP listen host for live route updates. If
`rib.bmp.host` and `rib.bmp.port` are both unset, the BMP listener stays
disabled.

`rib.bmp.port` (int, default 0): BMP listen port for live route updates. If only
one BMP field is set, the other defaults to `::1` or `11019`.

If configured with no BMP peer connected yet, the agent still runs and ASN
labels stay empty until routes arrive.

When both backends are enabled, ASN lookup uses the RIB first and MMDB as a
fallback. City lookup comes from MMDB.

## Prometheus metrics

Interface counters (from BPF per-CPU hash map, updated in kernel). The `family`
label is `"ipv4"`, `"ipv6"`, or `"other"` for non-IP traffic (e.g. ARP):

- `rfm_interface_rx_bytes_total{ifname, family}`
- `rfm_interface_tx_bytes_total{ifname, family}`
- `rfm_interface_rx_packets_total{ifname, family}`
- `rfm_interface_tx_packets_total{ifname, family}`

Flow gauges (rolled up by enrichment labels):

- `rfm_flow_bytes{ifname, direction, proto, src_asn, dst_asn, src_city, dst_city}`
- `rfm_flow_packets{ifname, direction, proto, src_asn, dst_asn, src_city, dst_city}`
- `rfm_flow_sampled_bytes{ifname, direction, proto, src_asn, dst_asn, src_city, dst_city}`
- `rfm_flow_sampled_packets{ifname, direction, proto, src_asn, dst_asn, src_city, dst_city}`

`rfm_flow_bytes` and `rfm_flow_packets` are estimated values scaled by
`agent.bpf.sample_rate`. `rfm_flow_sampled_bytes` and `rfm_flow_sampled_packets`
are the raw sampled values before scaling.

Collector health:

- `rfm_collector_active_flows`
- `rfm_collector_dropped_events_total`
- `rfm_collector_forced_evictions_total`
- `rfm_errors_total{subsystem}`

`rfm_errors_total{subsystem}` currently uses `bpf_map`, `ring_buffer`, and
`ipfix`.

## Visualization

An early Grafana dashboard is included at `grafana/dashboard.json`.

![Prometheus](grafana/prometheus.jpg)

Screenshot from
[Cloudflare Network Flow](https://developers.cloudflare.com/network-flow/)
(free):

![IPFIX](grafana/ipfix.jpg)

It is intentionally a starting point, not a finished observability product. The
current dashboard covers the basic operational views:

- aggregate ingress and egress traffic
- per-interface traffic breakdown
- protocol share
- ASN and city summaries
- collector health and error panels

The exporter already exposes enough structure to build more visualizations than
the bundled dashboard currently shows. The shipped dashboard should be treated
as a reference layout for the current metric set, not as the limit of what can
be derived from RFM data in Grafana.

## CLI

The current CLI surface is intentionally small:

- `rfm agent`

Control plane subcommands, runtime status, and RIB inspection are planned.

## IPFIX export

IPFIX export is optional and uses one UDP collector configured by
`agent.ipfix.host` and `agent.ipfix.port`.

The exporter uses `vmware/go-ipfix` for standards-compliant message encoding and
owns the UDP socket itself. That lets RFM exclude only its own export traffic
from recursive re-export while still observing unrelated traffic sent to the
same collector address and port.

## NixOS module

Example:

```nix
{ pkgs, ... }:

{
  services.rfm = {
    enable = true;
    settings.agent = {
      interfaces = [ "eth0" "tailscale0" ];
      bpf.sample_rate = 50;
      ipfix.host = "127.0.0.1";
      ipfix.port = 4739;
      prometheus.port = 9669;
      enrich.mmdb.asn_db = "${pkgs.dbip-asn-lite}/share/dbip/dbip-asn-lite.mmdb";
      enrich.mmdb.city_db = "${pkgs.dbip-city-lite}/share/dbip/dbip-city-lite.mmdb";
      enrich.rib.bmp.host = "127.0.0.1";
      enrich.rib.bmp.port = 11019;
    };
  };
}
```

The module generates a TOML config file and runs rfm as a systemd service with
automatic restart on failure. `agent.ipfix.*` and `agent.enrich.*` are available
through typed module options.

## Scope and non-goals

RFM is a lightweight flow telemetry agent, not a full traffic analysis platform.
A few deliberate choices follow from that:

The BPF programs capture only the fields needed for basic flow identification:
IP addresses, L4 ports, protocol number, interface, direction, and packet
length. They do not extract TCP flags, ToS/DSCP, TTL, IPv6 flow labels, or ICMP
type/code. Adding these fields would widen the per-event wire struct, increase
ring buffer pressure, and expand the IPFIX template surface for information that
most lightweight deployments never query. Operators who need TCP flag analysis,
QoS-aware accounting, or deep header inspection should consider ntopng or pmacct
instead.

Prometheus flow gauges are intentionally rolled up by enrichment labels
(interface, direction, protocol, ASN, city). Source and destination ports are
not included as Prometheus labels. With `max_flows` defaulting to 65536 and
ephemeral source ports ranging from 32768 to 60999, adding port labels would
create maybe 10k+ unique time series per scrape interval, most of which are seen
once and never again. This kind of high cardinality churn is expensive for
Prometheus to ingest and store. Port level flow records are available through
the IPFIX push path, where a downstream collector (goflow2 or similar, or flow
collector platforms with IPFIX support like Cloudflare Magic Network Monitoring)
is better suited to handle them.

## Comparison with other tools

The tools below all receive NetFlow/sFlow/IPFIX from routers, and some can also
capture packets directly (ntopng via libpcap/PF_RING, pmacct via pmacctd,
FastNetMon via AF_PACKET, nfdump via nfpcapd). rfm takes a different approach:
it captures packets directly in the kernel via eBPF TC programs. No flow export
configuration on the device, no separate collector, no message queue.

| Tool                                                       | Type                       | Infrastructure                | BGP/BMP                       | License              |
| ---------------------------------------------------------- | -------------------------- | ----------------------------- | ----------------------------- | -------------------- |
| rfm                                                        | eBPF agent (single binary) | Prometheus                    | BMP (inline)                  | AGPLv3               |
| [Akvorado](https://github.com/akvorado/akvorado)           | Flow receiver              | Kafka + ClickHouse + Redis    | BMP; SNMP/gNMI for interfaces | AGPLv3               |
| [goflow2](https://github.com/netsampler/goflow2)           | Flow receiver              | Kafka or file                 | GeoIP only                    | BSD-3                |
| [ntopng](https://github.com/ntop/ntopng)                   | Packet capture + DPI       | Redis + optional DB           | None                          | GPLv3 / commercial   |
| [pmacct](https://github.com/pmacct/pmacct)                 | Multi-daemon suite         | Kafka, PG, MySQL              | BGP + BMP + RPKI              | GPLv2+               |
| [kTranslate](https://github.com/kentik/ktranslate)         | Flow receiver              | 14+ output sinks              | GeoIP only                    | Apache-2.0           |
| [FastNetMon](https://github.com/pavel-odintsov/fastnetmon) | DDoS detection             | Prom, Kafka, ClickHouse       | BGP (output only)             | GPL-2.0 / commercial |
| [nfdump](https://github.com/phaag/nfdump)                  | Flow receiver + CLI        | Flat files                    | GeoIP only                    | BSD                  |
| [ElastiFlow](https://www.elastiflow.com)                   | Flow receiver              | ES, OpenSearch, Splunk, Kafka | GeoIP only                    | Proprietary          |

### Footprint and simplicity

rfm is a single binary with a single TOML config file. There are no external
dependencies at runtime: no database, no message queue, no Redis, no web server
beyond the built-in Prometheus endpoint. Typical RSS is around 10 MB.

Most alternatives require significant supporting infrastructure:

- **Akvorado**: Kafka + ClickHouse + Redis, four internal services (inlet,
  outlet, orchestrator, console)
- **ntopng**: Redis, optionally Elasticsearch or ClickHouse, nProbe (separate
  commercial product) for NetFlow/sFlow collection
- **pmacct**: seven daemons (pmacctd, nfacctd, sfacctd, uacctd, pmbgpd, pmbmpd,
  pmtelemetryd) each with its own config file and output plugins
- **ElastiFlow**: Elasticsearch or OpenSearch cluster

Even the lighter tools in the comparison (goflow2, nfdump, kTranslate) are flow
receivers that need routers to be configured for NetFlow/sFlow export and
typically feed into a downstream pipeline for storage and visualization.

rfm replaces that entire chain with a single process: capture, aggregation,
enrichment, and Prometheus export all happen in one binary, configured by one
file.

### Performance

rfm's eBPF TC programs run in the kernel with zero-copy delivery to userspace
via a ring buffer. Packet sampling (configurable 1-in-N) reduces ring buffer
throughput. Interface counters are updated on every packet regardless of
sampling, with no userspace involvement. The Prometheus exporter reads the BPF
map directly at scrape time.

Compared to libpcap-based tools (ntopng, pmacctd), eBPF TC avoids the overhead
of copying every packet to userspace. rfm only copies sampled flow metadata (56
bytes per event), not full packet contents. Compared to flow receivers
(Akvorado, goflow2), rfm eliminates the intermediate UDP export step entirely.

Performance under sustained high packet rates depends on the sample rate, ring
buffer size, and flow table limits, all of which are tunable.

### Container and Kubernetes use

rfm can run inside Docker containers or Kubernetes pods with `CAP_BPF` +
`CAP_NET_ADMIN` (or privileged mode). The host kernel must be Linux 6.12+.

Most flow receivers (Akvorado, goflow2, nfdump, ElastiFlow) cannot do
per-container flow monitoring. They are passive UDP listeners that depend on
external flow export from routers. The eBPF tools that can monitor per-container
traffic are either tied to a specific CNI (Cilium Hubble requires Cilium, Calico
flow logs require Calico) or target broader Kubernetes observability (Microsoft
Retina is CNI-agnostic but is a larger platform).

rfm is CNI-agnostic and does not require any particular network plugin. It
attaches TC programs to whatever interfaces are available in its network
namespace. This makes it usable as:

- a **DaemonSet** on each node (with host networking), attaching to container
  veth interfaces on the host side
- a **sidecar** inside a pod, monitoring that pod's network interfaces directly

The DaemonSet pattern is standard for eBPF-based monitoring (used by Hubble,
Retina, and Calico), but rfm's small footprint also makes the sidecar model
practical where per-pod isolation is needed.

### When to use something else

- **Deep packet inspection** (TCP flags, application protocol detection, payload
  analysis): ntopng
- **Collecting flows from hardware routers** that already export
  NetFlow/sFlow/IPFIX: Akvorado, goflow2, or nfdump
- **Historical flow storage and forensic queries**: nfdump or Akvorado with
  ClickHouse
- **DDoS detection and automated BGP blackhole mitigation**: FastNetMon
- **Turnkey web dashboard** without Grafana: ntopng or Akvorado

## Sponsorship disclaimer

[![NetActuate](https://cdn.prod.website-files.com/68079f156771d94adbf74490/6808bfbb66d18fea1371c72b_logo.svg)](https://netactuate.com)

This project is generously supported and tested on infrastructure provided by
[NetActuate](https://netactuate.com). The views and content of this project are
solely those of the authors and do not imply endorsement by NetActuate.
NetActuate provides global bare metal and cloud infrastructure with a strong
focus on performance, reliability, and geographic reach. Their platform enables
rapid deployment across diverse regions, making it well suited for
network-intensive and distributed systems workloads.

## License

Everything under `bpf/` is GPLv2 to satisfy kernel BPF requirements. Everything
else is AGPLv3.
