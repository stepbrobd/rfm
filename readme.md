# RFM

RFM (Router Flow Monitor) is an eBPF-based network flow analysis agent for Linux
BGP routers. It attaches TC programs to network interfaces, collects per-flow
traffic statistics with configurable sampling, enriches flows with BGP RIB
metadata via BMP, and exports the results to Prometheus.

The goal is a single `rfm` binary that:

- attaches TC programs for bidirectional flow observation
- keeps BPF behavior fully map-driven and stateless
- enriches flows in userspace with BGP RIB data from BMP
- exports Prometheus metrics
- exposes runtime control over a Unix domain socket
- reserves XDP for firewall fast-path features

## License

Everything under `bpf/` is GPLv2 to satisfy kernel BPF requirements. Everything
else is AGPLv3.
