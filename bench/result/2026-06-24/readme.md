# RFM Benchmark Run 2026-06-24 (Grid'5000 Nancy, gros, DPDK line rate, routed KaVLAN)

Produced by bench/workload/*.nu on the nodes below. See *.json files in this
directory. This run extends 2026-06-21 (Grenoble dahu, kernel pktgen, ~2.2 Mpps
ceiling) by driving the real-NIC tests with a DPDK generator at 25GbE line rate
(~14.4 Mpps received).

## Testbed

- Site/cluster: Grid'5000 Nancy, cluster `gros`.
- Nodes: 2x gros (1x Xeon Gold 5220, 18c/36t, 1 NUMA, 96 GB; 2x Mellanox
  ConnectX-4 Lx 25GbE SFP28, mlx5_core). Two usable data NICs per node.
- Isolation: routed KaVLAN, VLAN id 4, subnet 10.16.0.0/18. `eno1np0` is in the
  vlan and carries the flood (data); `eno2np1` stays on the production net and
  carries SSH control, so the flood never starves the control path.
- OAR job: 6697722 (oarsub -t deploy, {type='kavlan'}/vlan=1 + gros/host=2,
  walltime 3h). Deployed with kadeploy3 into vlan 4 (success on both nodes). The
  postinstall needed `--disable-hacks force-net-name` added to the deploy YAML:
  gros is in the postinstall's udev_245_hack_clusters list, whose force-net-name
  hack does `chroot DSTDIR /bin/true`, which fails on NixOS (no /bin/true); the
  flag skips that hack. dahu does not hit this.
- Image: ~/g5k-image/nixos-x86_64-linux (the bench base, NixOS 26.11
  20260619.d4fea6b), kernel 6.18.35. Agents baked in: rfm, netobserv-ebpf-agent
  v1.11.5, hsflowd 2.1.26-1 (mod_epcap.so + mod_psample.so), goflow2, nu,
  ethtool, plus DPDK (dpdk-testpmd, pktgen, rdma-core).

## Roles

- DUT (device under test): gros-59, data 10.16.0.59 (eno1np0, MAC
  98:03:9b:b0:c1:2e), control 172.16.66.187 (eno2np1). Runs rfm and the baseline
  agents.
- Generator: gros-79, data 10.16.0.79 (eno1np0), control 172.16.66.207
  (eno2np1).

Node-to-node in the vlan: ping 0% loss, ~0.25 ms RTT (L2 direct).

## Generator: DPDK at line rate

The real-NIC tests use dpdk-testpmd in `txonly --txonly-multi-flow` on the
generator's eno1np0. The mlx5 PMD is bifurcated: DPDK transmits while the kernel
keeps the NIC bound (no vfio takeover, no IOMMU needed), so control stays up.
Hugepages (2M) are allocated at runtime since the deployed cmdline carries no
hugepage params. The generator offers ~35.4 Mpps of 64B (near 25GbE line rate,
~18.1 Gbps) with the source IP varied across flows for RSS spread; the DUT
receives ~14.4 Mpps across 36 RX queues (the rest is shed at the NIC). This is
6.5x the ~2.2 Mpps that single-thread kernel pktgen could offer on 2026-06-21.

DPDK 64B generation needs an mlx5 (bifurcated) NIC. dahu's Intel X710 (i40e)
cannot do it (DPDK there requires a full vfio takeover of the node's single
usable data NIC, which is also its control path), which is why this run moved to
Nancy gros.

## Methodology notes

- Single-node microbench (overhead, accuracy, tune, scale): unchanged from
  2026-06-21. Kernel pktgen over a veth pair, rfm monitors the peer; ground
  truth = pktgen send counts
  - rfm per-CPU interface counters (exact). Does not touch the real NIC, so it
    is unaffected by the DPDK generator or the RX-queue count.
- Two-node real NIC at DPDK line rate (realnic, rss, progcost): rfm monitors
  eno1np0 under the ~14.4 Mpps DPDK flood, 36 RX queues. N=1 is excluded from
  realnic and rss: sampling every packet at line rate cannot drain through the
  single userspace collector (14.4M events/s), which starves the agent. N>=10 is
  fine.
- Head-to-head (headtohead): measured at a MODERATE ~2.2 Mpps load (kernel
  pktgen), not at line rate. At ~14.4 Mpps the NIC RX softirq baseline alone is
  ~34.6 of 36 cores and saturates the receive path, leaving no headroom to
  separate the agents. The generator type does not affect a DUT-side per-agent
  comparison at matched offered load. Each agent is force-killed before the next
  (see the contamination note under head-to-head below).
- Fair cost metric in head-to-head = system-wide busy cores (delta of
  /proc/stat: NIC softirq + capture + userspace), matched 1-in-N across agents.

## Result file manifest

- overhead.json single-node: datapath overhead vs N (veth, 5M pkts/N)
- acc-N100-M1000.csv single-node: per-flow accuracy, M/N=10
- acc-N100-M10000.csv single-node: per-flow accuracy, M/N=100
- tune.json single-node: ring_buf_size / wakeup_batch sweep at N=1
- scale-N100.json single-node: multi-core scaling, N=100 (linear regime)
- scale-N1.json single-node: multi-core scaling, N=1 (contention regime)
- realnic.json two-node DPDK line rate: overhead vs N at ~14.4 Mpps (N=1
  excluded)
- rss.json two-node DPDK line rate: RSS RX-queue sweep at N=100
- headtohead.json two-node moderate ~2.2 Mpps: rfm vs
  pmacctd/softflowd/netobserv/hsflowd
- progcost.json two-node DPDK line rate: per-packet eBPF program cost
  (runs_per_rx, avg ns)
- progcost.txt human-readable per-packet cost summary + interpretation

## Headline results (see the json files for the full sweeps)

Single-node (veth + pktgen, ~1.0-1.36 Mpps single thread):

- overhead: exact per-CPU counters 100.000% at every N; ring drops only at N=1
  (1.08M/5M); kernel 41.3 ns/pkt (N=1024) -> 167.9 ns/pkt (N=1); userspace 0.008
  -> 0.691 cores.
- accuracy: per-flow mean rel-err under the Duffield sqrt(N/M) bound. M/N=10 ->
  0.258 (coverage 0.999), M/N=100 -> 0.079 (coverage 0.997).
- tune: ring_buf_size 256K -> 4M eliminates the N=1 drops at ~no CPU cost.
- scale (exact counters 100% throughout): N=100 scales linearly 1->16 cores to
  15.2 Mpps and tops out ~17.6 Mpps at 32 (gros has 18 physical cores; kernel
  1.13 c, 0 drops); N=1 plateaus ~4.2 Mpps with kernel cores super-linear 0.08
  -> 23.0 c and drops 0 -> 54M.

Two-node real mlx5 NIC at DPDK line rate (offered ~35 Mpps, received ~14.4 Mpps
of 64B):

- realnic (overhead vs N): N=1024 -> 102 ns/pkt, 0 drops, 0.105 cores/Mpps;
  N=100 -> 106 ns/pkt, 30k drops, 0.128 cores/Mpps; N=10 -> 123 ns/pkt, 19.2M
  drops, 0.145 cores/Mpps. rfm monitors a 25G line-rate 64B flood at N=100 for
  0.128 cores/Mpps with near-zero ring drops. N=1 is infeasible at this rate
  (excluded).
- rss: at N=100, exact-counter throughput scales with RX queues 1.15 Mpps (1
  queue) -> 14.32 Mpps (32 queues), 0 ring drops at every queue count, kernel
  0.05 -> 1.39 c. About 32 queues are needed to absorb 25G of 64B; a single
  queue caps near 1.15 Mpps.
- progcost: every in-kernel agent's TC/TCX program runs per-packet
  (runs_per_rx=1.0) even at line rate; rfm 105 ns, hsflowd 91 ns, netobserv 65
  ns in-program.

Head-to-head (matched 1/100, system-wide busy cores, moderate ~2.2 Mpps,
9.74-core softirq baseline): rfm +0.97 (0 drops); netobserv +0.75; hsflowd
+0.84; softflowd +13.8; pmacctd +11.0. The three in-kernel eBPF agents cluster
around +0.8 cores; the libpcap tools are 11 to 18x heavier. The cost gap is
about the kernel-to-userspace boundary (sample in kernel vs copy every packet to
userspace), not about whether the agent keeps per-flow state: netobserv keeps a
per-CPU flow hash and is still cheap.

Correction vs 2026-06-21: that run reported netobserv +17.0 and hsflowd +15.2,
in the same heavy class as the libpcap tools. Those numbers were contaminated.
headtohead.nu killed each agent with SIGINT, and softflowd/pmacctd (libpcap) did
not always exit, so orphan captures kept copying every packet and inflated the
agents measured after them (netobserv, hsflowd). The 2026-06-21 progcost.txt is
internally inconsistent with this: it lists netobserv at 74 ns and hsflowd at 98
ns per packet, which at ~2.2 Mpps is ~0.16 cores, not +15 to +17. This run
force-kills each agent before the next, and the corrected costs match progcost.
The headline becomes "in-kernel eBPF agents are cheap; libpcap tools are 11-18x
heavier", not "rfm is uniquely cheap".

Caveat: the head-to-head is at ~2.2 Mpps because line rate saturates the receive
path; the line-rate story for rfm itself is in realnic/rss/progcost. No energy
numbers: gros has a wattmeter, but gros-59's power telemetry (wattmetre, PDU,
and BMC) all reported 0 W during the run, so per-agent watts could not be
captured. No RFC2544 binary-search MLFR and no cgroup memory.peak were captured.
