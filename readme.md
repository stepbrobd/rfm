# RFM

RFM (Router Flow Monitor) is an eBPF-based network flow analysis agent for Linux
BGP routers. It attaches TC programs to network interfaces, collects per-flow
traffic statistics with configurable sampling, enriches flows with BGP RIB
metadata via BMP, and exports the results to Prometheus.

Requirements:

- Linux 6.12 or newer (TCX, `bpf_ktime_get_boot_ns`)
- Go 1.23+
- Root or `CAP_BPF` + `CAP_NET_ADMIN`

The goal is a single `rfm` binary that:

- Attaches TC programs for bidirectional flow observation
- Keeps BPF behavior fully map-driven and stateless
- Enriches flows in userspace with BGP RIB data from BMP
- Exports Prometheus metrics
- Exposes runtime control over a Unix domain socket
- Reserves XDP for firewall fast-path features

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
   (ASN, city) before emitting metrics.

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
host = "::"
port = 9669
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
eviction. Accepts any Go duration string (e.g. "10s", "1m", "500ms"). Must parse
to a positive duration.

### `agent.prometheus`

`host` (string, default "::"): Address to bind the Prometheus metrics HTTP
server to. Use "::" for all interfaces (IPv4 and IPv6), "0.0.0.0" for IPv4 only,
or "127.0.0.1" to restrict to localhost.

`port` (int, default 9669): TCP port for the metrics server. Must be between 1
and 65535.

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

## NixOS module

Example:

```nix
services.rfm = {
  enable = true;
  settings.agent = {
    interfaces = [ "eth0" "tailscale0" ];
    bpf.sample_rate = 50;
    prometheus.port = 9669;
  };
};
```

The module generates a TOML config file and runs rfm as a systemd service with
automatic restart on failure.

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
