# RFM

RFM (Router Flow Monitor) is an eBPF-based network flow analysis agent for Linux
routers. It attaches TC programs to network interfaces, collects per-flow
traffic statistics with configurable sampling, optionally enriches flows from a
live BMP-fed RIB and/or MMDB ASN/city databases, and exports the results to
Prometheus. IPFIX export is planned.

Requirements:

- Linux 6.12 or newer (TCX, `bpf_ktime_get_boot_ns`)
- Go 1.23+
- Root or `CAP_BPF` + `CAP_NET_ADMIN`

Current scope:

- Attaches TC programs for bidirectional flow observation
- Keeps BPF behavior fully map-driven and stateless
- Optionally enriches flows in userspace with BMP/RIB data, MMDB data, or both
- Exports Prometheus metrics
- Ships a typed NixOS module and VM coverage

Planned:

- Unix socket control plane
- IPFIX export
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
rather than compiled-in constants. Config changes currently trigger a full
unload and reload of the BPF programs.

### Data path

1. TC programs classify each packet by direction, protocol family, and 5-tuple.
   Every packet updates per-CPU interface counters. Sampled packets (1-in-N)
   emit a flow event to a ring buffer.
2. The userspace collector reads events from the ring buffer, converts
   `CLOCK_BOOTTIME` timestamps to wall clock time, and aggregates flows into an
   in-memory table keyed by
   `(ifindex, direction, protocol,
   src/dst address, src/dst port)`.
3. Flows are evicted after a configurable idle timeout. When the flow table is
   full, the oldest flow is forcibly evicted.
4. At scrape time, the Prometheus exporter reads the BPF interface counters map
   directly and iterates the flow table, rolling up flows by enrichment labels
   (ASN, city) before emitting metrics. With no enrichment configured, those
   labels stay empty and the agent still runs normally.

## Configuration

rfm reads a TOML config file (default `/etc/rfm/rfm.toml`). Unknown keys are
rejected at load time to catch typos. Example:

```toml
[agent]
interfaces = ["eth0", "tailscale0"]

[agent.bpf]
sample_rate = 100
ring_buf_size = 262144

[agent.collector]
max_flows = 65536
eviction_timeout = "30s"

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
Must be greater than 0 and should be a power of two. Larger buffers reduce the
chance of dropped events under burst traffic.

### `agent.collector`

`max_flows` (int, default 65536): Maximum number of active flows held in memory.
Must be >= 0. When the table is full, the oldest flow is forcibly evicted. A
value of 0 means unlimited.

`eviction_timeout` (string, default "30s"): How long a flow can be idle before
eviction. Accepts any Go duration string (e.g. "10s", "1m", "2s"). Minimum value
is 1s.

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

Interface counters (from BPF map, zero overhead). The `family` label is
`"ipv4"`, `"ipv6"`, or `"other"` for non-IP traffic (e.g. ARP):

- `rfm_interface_rx_bytes_total{ifname, family}`
- `rfm_interface_tx_bytes_total{ifname, family}`
- `rfm_interface_rx_packets_total{ifname, family}`
- `rfm_interface_tx_packets_total{ifname, family}`

Sampled flow gauges (rolled up by enrichment labels):

- `rfm_flow_bytes{ifname, direction, proto, src_asn, dst_asn, src_city, dst_city}`
- `rfm_flow_packets{ifname, direction, proto, src_asn, dst_asn, src_city, dst_city}`

Collector health:

- `rfm_collector_active_flows`
- `rfm_collector_dropped_events_total`
- `rfm_collector_forced_evictions_total`
- `rfm_errors_total{subsystem}`

`rfm_errors_total{subsystem}` currently uses `bpf_map` and `ring_buffer`.

## CLI

The current CLI surface is intentionally small:

- `rfm agent`

Control plane subcommands, runtime status, and RIB inspection are planned.

## NixOS module

Example:

```nix
services.rfm = {
  enable = true;
  settings.agent = {
    interfaces = [ "eth0" "tailscale0" ];
    bpf.sample_rate = 50;
    prometheus.port = 9669;
    enrich.mmdb.asn_db =
      "${pkgs.dbip-asn-lite}/share/dbip/dbip-asn-lite.mmdb";
    enrich.mmdb.city_db =
      "${pkgs.dbip-city-lite}/share/dbip/dbip-city-lite.mmdb";
    enrich.rib.bmp.host = "127.0.0.1";
    enrich.rib.bmp.port = 11019;
  };
};
```

The module generates a TOML config file and runs rfm as a systemd service with
automatic restart on failure. `agent.enrich.*` is available through typed module
options.

## Comparison with other tools

|                     | rfm                                                  | ntopng                                        | pmacct                                    |
| ------------------- | ---------------------------------------------------- | --------------------------------------------- | ----------------------------------------- |
| Capture method      | eBPF TC (zero-copy ring buffer)                      | libpcap / PF_RING / nProbe                    | libpcap / NetFlow / sFlow / BMP           |
| Resource footprint  | Single static binary, ~10 MB RSS                     | Web UI + Redis + optional DB                  | Multiple daemons (pmacctd, nfacctd, etc.) |
| BGP integration     | Inline BMP receiver, same process                    | External nProbe agent or NetFlow              | Separate BGP daemon (bgp_daemon)          |
| Flow granularity    | Per-packet sampling in kernel, userspace aggregation | Full packet capture or NetFlow                | Depends on input plugin                   |
| Output              | Prometheus (pull)                                    | Web dashboard, Elasticsearch, MySQL, InfluxDB | Kafka, PostgreSQL, print, etc.            |
| Configuration       | Single TOML file                                     | Web UI + config files                         | Multiple configuration files per daemon   |
| Deployment          | Single binary or NixOS module                        | Packages for most distros, Docker             | Packages for most distros                 |
| Kernel requirements | Linux 6.12+                                          | Any (libpcap)                                 | Any (libpcap) or none (NetFlow/sFlow)     |

ntopng is a full network monitoring suite with a web interface, historical
storage, and deep protocol inspection. It targets operators who need a turnkey
dashboard and are willing to run the supporting infrastructure (Redis,
optionally a database backend).

pmacct is a collection of daemons that consume traffic data from various sources
(libpcap, NetFlow, sFlow, BMP) and write to various backends (Kafka, PostgreSQL,
memory tables). It is highly flexible but requires assembling multiple
components and configuration files.

rfm occupies a narrower niche: lightweight flow telemetry for Linux routers that
already run Prometheus. It trades breadth of features for minimal resource usage
and operational simplicity. The entire deployment is one binary, one config
file, and one metrics endpoint.

## License

Everything under `bpf/` is GPLv2 to satisfy kernel BPF requirements. Everything
else is AGPLv3.
