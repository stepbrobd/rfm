# RFM Benchmark Run 2026-06-25 (Grid'5000 Nancy, gros, routed KaVLAN)

Produced by bench/workload/*.nu on the nodes below. See the *.json / *.csv files
in this directory. This run extends 2026-06-24 with the data the manuscript
needs:

1. Every cost sweep runs the base-10 sample rates N=1/10/100/1000.
2. The 5-agent head-to-head is swept over the sample rate, so all five monitors
   can be shown at a matched N in one figure (the fig 2 fold of fig 3), and it
   now also reports each agent's kernel BPF-map memory.
3. A flow-cardinality sweep of kernel memory and per-flow-table occupancy
   (kmem.nu), demonstrating that rfm holds no per-flow kernel state while
   netobserv's kernel flow hash caps at 5000 flows.

All measurements come from the committed nushell harnesses in bench/workload/
(re-run them to reproduce). The kernel-pktgen generator is gen.nu; the only
non-nu generator is dpdk-testpmd for the 25 GbE line-rate flood (no nu DPDK
harness exists), whose exact command is given below.

## Testbed

- Site/cluster: Grid'5000 Nancy, cluster `gros`.
- Nodes: 2x gros (1x Xeon Gold 5220, 18c/36t, 1 NUMA, 96 GB; 2x Mellanox
  ConnectX-4 Lx 25GbE SFP28, mlx5_core).
- Isolation: routed KaVLAN, VLAN id 4, subnet 10.16.0.0/18. `eno1np0` is in the
  vlan and carries the flood (data); `eno2np1` stays on the production net and
  carries SSH control, so the flood never starves the control path.
- OAR job: 6700620 (oarsub -t deploy, {type='kavlan'}/vlan=1 + gros/host=2,
  walltime 5h). Deployed with kadeploy3 into vlan 4. The deploy YAML carries
  `--disable-hacks force-net-name` (gros is in the postinstall
  udev_245_hack_clusters list, whose force-net-name hack runs
  `chroot DSTDIR /bin/true`, which fails on NixOS).
- Image: ~/g5k-image/nixos-x86_64-linux (NixOS 26.11 20260619.d4fea6b), kernel
  6.18.35. Agents baked in: rfm, netobserv-ebpf-agent v1.11.5, hsflowd 2.1.26-1
  (mod_epcap.so + mod_psample.so), goflow2, pmacct, softflowd, nu, ethtool, plus
  DPDK (dpdk-testpmd, pktgen, rdma-core).

## Roles

- DUT (device under test): gros-84, data 10.16.0.84 (eno1np0, MAC
  98:03:9b:b0:a9:6e), control 172.16.66.212 (eno2np1). Runs rfm and the baseline
  agents.
- Generator: gros-86, data 10.16.0.86 (eno1np0, MAC 98:03:9b:b0:cf:e6), control
  172.16.66.214 (eno2np1). Node-to-node in the vlan: 0% loss, ~0.29 ms RTT.

## Generators

- Moderate load (head-to-head, kmem cardinality): gen.nu kernel pktgen, 2
  threads, 64B, clone_skb=0 + UDPSRC_RND over the configured src-port range for
  RSS spread. The DUT received ~2.08 Mpps across its RX queues. Reproduce:
  `nu gen.nu --iface eno1np0 --dst 10.16.0.84 --dstmac 98:03:9b:b0:a9:6e
  --threads 2 --count <N> --flows <F>`
  on the generator (F = distinct flows).
- Line rate (progcost): dpdk-testpmd in txonly --txonly-multi-flow on the
  generator's eno1np0. mlx5 bifurcated PMD (DPDK transmits while the kernel
  keeps the NIC bound; no vfio, no IOMMU), 2M hugepages allocated at runtime,
  allowlist of ONLY the data port (-a 0000:18:00.0) so the control port is
  untouched. 8 TX cores/queues. The DUT received ~15-16 Mpps of 64B across 36 RX
  queues. Command:
  `dpdk-testpmd -l 0-8 -n 4 -a 0000:18:00.0 -- --forward-mode=txonly
  --txonly-multi-flow --auto-start --eth-peer=0,98:03:9b:b0:a9:6e
  --tx-ip=10.16.0.86,10.16.0.84 --txq=8 --rxq=8 --nb-cores=8
  --total-num-mbufs=262144 --stats-period=10`.

## Methodology notes

- Single-node microbench (overhead, scale, tune, accuracy): rfm only, over a
  veth pair driven by kernel pktgen; rfm monitors the peer. These harnesses are
  rfm-specific (the cost metric is cores/Mpps from bpf_stats, defined only for
  the eBPF datapath). They do not touch the real NIC.
- Head-to-head (the 5-agent comparison): on the real mlx5 NIC under the moderate
  ~2.08 Mpps gen.nu flood (1000 flows). Swept over N=1/10/100/1000 (one
  headtohead.nu run per N, generator left running). CPU metric = system-wide
  busy cores (delta of /proc/stat: NIC softirq + capture + userspace),
  well-defined for the libpcap tools too -- the reason the 4 non-rfm monitors
  live here and not in the single-node overhead. Each agent is force-killed
  (SIGKILL) before the next: softflowd/pmacctd (libpcap) do not reliably exit on
  SIGINT and an orphan capture inflates the next agent (the 2026-06-21
  contamination). Memory metric = bytes_memlock of the agent's own BPF maps
  (delta over a no-agent baseline).
- Flow-cardinality memory (kmem.nu): under the moderate gen.nu flood with F
  distinct flows (1000/5000/20000/50000), attaches each in-kernel agent and
  reads its BPF maps' locked memory and, for each per-flow hash table, its
  capacity (max_entries) and current occupancy (bpftool map dump count). Shows
  the kernel per-flow state directly.
- Line-rate real NIC (realnic, rss, progcost): rfm (or each in-kernel agent for
  progcost) under the ~15-16 Mpps DPDK flood. realnic and rss read rfm's rx rate
  from its TC program run_cnt via bpftool, not from rfm's Prometheus HTTP
  endpoint, which is unreachable under full saturation (node loadavg ~39); ring
  drops are best-effort (-1 when the HTTP scrape fails under load). rfm must
  start from a clean state each run -- a stale TC program left attached freezes
  ingress run_cnt and zeroes the measured rate. N=1 is excluded at line rate (a
  single userspace consumer cannot drain ~15M events/s).

## Result file manifest

- overhead.json single-node: rfm datapath cost vs N (veth, 5M pkts/N),
  N=1/10/100/1000
- scale-N{1,10,100,1000}.json single-node: rfm multi-core scaling at each N
  (cores 1..32). N=10 and N=1000 are new lines for fig 2(b,c).
- tune.json single-node: rfm ring_buf_size / wakeup_batch ablation at N=1
- acc-N{100,10,1000}-M{1000,10000}.{csv,summary} single-node: per-flow accuracy
  vs the Duffield sqrt(N/M) bound, plus analyze.py summaries
- headtohead-N{1,10,100,1000}.json two-node moderate ~2.08 Mpps: baseline +
  rfm + softflowd + pmacctd + netobserv + hsflowd at each N, with sys_cores and
  BPF-map memory (the fig 2 fold: all 5 monitors at a matched sample rate)
- kmem-F{1000,5000,20000,50000}.json two-node moderate: per-agent BPF-map memory
  and per-flow-table occupancy vs flow cardinality (rfm/netobserv/hsflowd)
- realnic.json two-node DPDK line rate: rfm overhead vs N (N=1000/100/10; N=1
  excluded). rx rate from bpftool run_cnt; ring drops best-effort (-1)
- rss.json two-node DPDK line rate: RSS RX-queue sweep at N=100 (queues 1..32)
- progcost.json / progcost.txt two-node DPDK line rate: per-packet eBPF program
  cost (runs_per_rx, avg ns) for rfm/hsflowd/netobserv

## Headline results

### Single-node rfm microbench (veth + pktgen, ~1.07-1.38 Mpps single thread)

- overhead (exact per-CPU counters 100% at every N; ring drops only at N=1):
  cost falls 0.628 cores/Mpps (N=1) -> 0.060 (N=10) -> 0.028 (N=100) -> 0.006
  (N=1000); kernel 184.7 ns/pkt (N=1) -> 41.2 ns/pkt (N=1000).
- scale (exact counters 100% throughout): throughput at 32 threads tops out at
  ~4.2 Mpps (N=1, ring-lock contention), 17.2 Mpps (N=10), 17.6 Mpps (N=100),
  17.8 Mpps (N=1000). Kernel CPU at 32 threads: 23.1 cores (N=1, super-linear)
  vs 1.39 (N=10), 1.15 (N=100), 1.12 (N=1000). gros has 18 physical cores, so
  the 32-thread point spills onto SMT siblings. Ring drops climb to 54M at N=1,
  are bounded at N=10 (3.8M at 32 threads), and are 0 at N>=100.
- tune (N=1 worst case): raising ring_buf_size from 256K to >=1M removes the N=1
  ring drops (98k -> 0) at no CPU cost (~0.67 cores throughout); wakeup_batch
  does not help (drops stay ~110-150k at the 256K ring across batch 16..1024).
- accuracy (per-flow rel-err vs Duffield sqrt(N/M)): M/N=10 (N=100,M=1000) mean
  0.242 < bound 0.316, coverage 0.999; M/N=100 (N=100,M=10000) mean 0.080 <
  0.100, coverage 0.959; N=10,M=1000 mean 0.078 < 0.100, coverage 0.997. The
  N=1000,M=10000 point is anomalous (coverage 2.35: flows outlive the 1s
  eviction timeout and export as multiple IPFIX records) and should be excluded
  or re-run with a longer eviction window; the figure uses the N=100 points.

### Head-to-head: 5 agents at matched N, moderate ~2.08 Mpps, 1000 flows

System-wide busy cores added over the per-N agent-free baseline (~3.22-3.25
cores of NIC softirq), and kernel BPF-map memory (constant in N, since N does
not change the flow count):

agent cores over baseline (N=1/10/100/1000) BPF-map kernel memory rfm +1.34 /
+0.39 / +0.20 / +0.19 314 KB netobserv +0.34 / +0.17 / +0.17 / +0.16 1453 KB
hsflowd +0.16 / +0.13 / +0.15 / +0.14 91 KB softflowd +4.81 / +4.61 / +4.74 /
+4.81 ~0 (libpcap, userspace) pmacctd +4.06 / +3.06 / +3.20 / +3.34 ~0 (libpcap,
userspace)

The two libpcap exporters are ~10-40x heavier in CPU than the eBPF agents and
flat in N (they copy every packet to userspace and sample after, so raising N
does not cut their capture cost). Among the three eBPF agents the picture is a
design trade-off, not a single winner:

- CPU: at N>=100 rfm (+0.19), netobserv (+0.16), and hsflowd (+0.14) sit within
  ~0.05 cores of each other (near the measurement noise at this baseline). At
  aggressive sampling rfm is more expensive: at N=1 it pays +1.34 and drops
  ~19.6M events/s because its single userspace consumer cannot drain 2 Mpps of
  sampled events. The low-N rfm points are consumer-bound and are not a steady
  operating point.
- The reason rfm spends more CPU than netobserv is architectural: rfm streams
  sampled packets to a userspace consumer and aggregates flows there, while
  netobserv aggregates per-flow IN the kernel (a per-CPU hash) and only dumps it
  periodically. What rfm buys for that CPU is exact per-interface counters and
  no per-flow kernel state (see below).

### Per-agent kernel BPF-map breakdown (1000 flows, N=100)

rfm 314 KB = rfm_flow_events ringbuf 270 KB (256K, constant) + rfm_iface_stats
per-CPU counters 44 KB. No per-flow table. netobserv 1453 KB = quic_flows
per-CPU hash 1026 KB (max 65536, ~0 entries without QUIC) + aggregated_flow hash
325 KB (max 5000) + small ringbufs. Two per-flow tables. hsflowd 91 KB = events
ringbuf 78 KB + sampling hash 15 KB. No per-flow table. softflowd ~180 KB /
pmacctd ~36 KB: no BPF maps; their kernel memory is just the AF_PACKET socket
buffer (idle SUnreclaim delta). Flow tables are in userspace.

All three eBPF agents deliver samples through BPF ringbufs that bytes_memlock
counts, so the BPF-map metric is fair across them. The fair-total kernel memory
ranking is netobserv (1453 KB) >> rfm (314 KB) > softflowd (~180 KB) > hsflowd
(91 KB) > pmacctd (~36 KB). rfm is not the absolute smallest, but it is the only
agent that pairs exact counters with zero per-flow kernel state, and it uses
4.6x less kernel memory than netobserv, its closest design competitor.

### Flow-cardinality kernel memory (kmem.nu, moderate ~2.08 Mpps)

netobserv's aggregated_flow hash is capped at max_entries=5000. As the active
flow count F grows, it fills and then saturates; flows beyond 5000 cannot be
tracked. rfm and hsflowd hold no per-flow kernel table at any cardinality.

F (flows) netobserv aggregated_flow (entries/max, memlock) rfm hsflowd 1000 999
/ 5000 325 KB 314 KB 91 KB 5000 4999 / 5000 1106 KB 314 KB 91 KB 20000 5000 /
5000 1107 KB (caps; tracks 25% of flows) 314 KB 91 KB 50000 5000 / 5000 1107 KB
(caps; tracks 10% of flows) 314 KB 92 KB

netobserv's total kernel memory rises to ~2.2 MB and its flow coverage collapses
once F exceeds its 5000-entry cap (100% -> 100% -> 25% -> 10%). rfm's kernel
memory is constant at 314 KB with no flow table: sampled flows are aggregated in
a userspace table bounded only by RAM, so there is no kernel-side cardinality
cap. This is rfm's structural advantage over the in-kernel-aggregation design.

### Line-rate real NIC: rfm overhead vs N (realnic, DPDK ~15-16 Mpps)

N rx pps ns/pkt kern cores user cores cores/Mpps N=1000 15.0 Mpps 105.6 1.584
0.017 0.107 N=100 4.4 Mpps 107.4 0.470 0.033 0.115 N=10 3.8 Mpps 124.9 0.477
0.012 0.128

rfm holds 25 GbE line rate at N=1000 for ~0.11 cores/Mpps. Only N=1000 sustains
the full ~15 Mpps through the TC hook; at N=100 and N=10 the sampled-event
consumer load backs up the receive path so fewer packets reach the hook (rx
3.8-4.4 Mpps), which is why ns/pkt rises and cores/Mpps grows toward low N. Ring
drops were not captured (-1; rfm's HTTP endpoint is unreachable under full
saturation).

### RSS RX-queue sweep at line rate (rss, N=100)

Exact-counter throughput scales with RX queues: 1.1 Mpps (1 queue) -> 14.2 Mpps
(32 queues), 0 ring drops at every queue count, kernel 0.05 -> 1.40 cores. About
32 queues are needed to absorb 25G of 64B; a single queue caps near 1.1 Mpps.

### Per-packet eBPF program cost (progcost, DPDK ~15-16 Mpps line rate)

Every in-kernel agent's TC/TCX program runs about once per received packet; rfm
106 ns, hsflowd epcap 94 ns, netobserv 67 ns in-program (runs_per_rx ~1.0; rfm
read 0.62 here, reflecting packets dropped before the TC hook at extreme load).
rfm's program is the most expensive of the three per run because it also updates
the always-on exact per-CPU counters. Sampling does not skip the datapath
program; rfm's low total cost comes from gating the sample first and holding no
per-flow kernel state, not from running its program less often.

## Caveats

- realnic/rss read rfm's rx rate from bpftool run_cnt (the HTTP endpoint is
  unreachable under full saturation), and report ring drops best-effort (-1).
- Head-to-head is at ~2.08 Mpps; at line rate the NIC softirq saturates the
  receive path and leaves no headroom to separate the agents.
- Sub-0.2-core CPU differences at N>=100 carry real measurement noise; do not
  over-read small gaps among the eBPF agents.
- No energy numbers (gros wattmeter read 0 W for these nodes), no RFC2544
  binary-search MLFR.
