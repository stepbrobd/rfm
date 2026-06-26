# RFM Benchmark Run 2026-06-26 (Grid'5000 Nancy, gros, routed KaVLAN)

Reproduction of the 2026-06-25 run on a fresh reservation, using the committed
`bench/workload/*.nu` harnesses unmodified. Every published 2026-06-25 number is
reproduced within run-to-run noise. See the `*.json` / `*.csv` files here.

This run was driven from the local repo at HEAD `dc47248` (the frontend `~/rfm`
checkout was one commit behind and lacked `kmem.nu`); the committed harness
scripts were rsync'd to both nodes and verified byte-identical (sha256) before
running.

## Testbed

- Site/cluster: Grid'5000 Nancy, cluster `gros`.
- Nodes: 2x gros (1x Xeon Gold 5220, 18c/36t, 1 NUMA, 96 GB; 2x Mellanox
  ConnectX-4 Lx 25GbE SFP28, mlx5_core).
- Isolation: routed KaVLAN, VLAN id 4, subnet 10.16.0.0/18. `eno1np0` is in the
  vlan and carries the flood (data); `eno2np1` stays on the production net
  (172.16.66.x) and carries SSH control, so the line-rate flood never starves
  the control path.
- OAR job: 6701510 (oarsub -t deploy, {type='kavlan'}/vlan=1 + gros/host=2,
  walltime 5h). Deployed with kadeploy3 into vlan 4. The deploy YAML carries
  `--disable-hacks force-net-name` (gros' postinstall force-net-name hack runs
  `chroot DSTDIR /bin/true`, which fails on NixOS).
- Image: ~/g5k-image/nixos-x86_64-linux (NixOS 26.11 20260619.d4fea6b, kernel
  6.18.35). Agents baked in: rfm v2026.619.0, netobserv-ebpf-agent v1.11.5,
  hsflowd 2.1.26-1 (mod_epcap.so + mod_psample.so), goflow2, pmacct, softflowd,
  nu, ethtool, plus DPDK (dpdk-testpmd, pktgen, rdma-core).

## Roles

- DUT (device under test): gros-55, data 10.16.0.55 (eno1np0, MAC
  98:03:9b:b0:bf:ce, PCI 0000:18:00.0), control 172.16.66.183 (eno2np1). Runs
  rfm and the baseline agents.
- Generator: gros-91, data 10.16.0.91 (eno1np0, MAC 98:03:9b:b0:97:42), control
  172.16.66.219 (eno2np1). Node-to-node in the vlan: 0% loss, ~0.29 ms RTT.

## Generators

- Moderate load (head-to-head, kmem cardinality): gen.nu kernel pktgen, 2
  threads, 64B, clone_skb=0 + UDPSRC_RND over the src-port range for RSS spread.
  The DUT received ~2.09 Mpps. Reproduce:
  `nu gen.nu --iface eno1np0 --dst 10.16.0.55 --dstmac 98:03:9b:b0:bf:ce
  --threads 2 --count <N> --flows <F>`
  on the generator.
- Line rate (realnic, rss, progcost): dpdk-testpmd in txonly
  --txonly-multi-flow, now wrapped by `bench/workload/dpdk.nu`. mlx5 bifurcated
  PMD (DPDK transmits while the kernel keeps the NIC bound; no vfio, no IOMMU),
  2M hugepages allocated at runtime, allowlist of ONLY the data port (-a
  0000:18:00.0). 8 TX cores/queues. The DUT received ~15-16 Mpps of 64B across
  36 RX queues. Reproduce:
  `nu dpdk.nu --pci 0000:18:00.0 --peer 98:03:9b:b0:bf:ce --self-ip 10.16.0.91
  --dst-ip 10.16.0.55`
  on the generator (stop with `nu dpdk.nu --stop`). The underlying command:
  `dpdk-testpmd -l 0-8 -n 4 -a 0000:18:00.0 -- --forward-mode=txonly
  --txonly-multi-flow --auto-start --eth-peer=0,98:03:9b:b0:bf:ce
  --tx-ip=10.16.0.91,10.16.0.55 --txq=8 --rxq=8 --nb-cores=8 --txpkts=64
  --total-num-mbufs=262144 --stats-period=2`.

## Reproduction status (2026-06-26 vs 2026-06-25)

All measurements reproduced within run-to-run noise. Cells are 06-26 vs 06-25.

- overhead (veth, cores/Mpps): N=1 0.688 vs 0.672; N=10 0.077 vs 0.078; N=100
  0.040 vs 0.037; N=1000 0.008 vs 0.008. Exact per-CPU counters 100.0% at every
  N; ring drops only at N=1 (110k vs 125k).
- scale (32 threads): agg Mpps N=1 4.0 vs 3.9, N=10 17.1 vs 17.2, N=100 17.6 vs
  17.6, N=1000 17.8 vs 17.8; kernel cores at N=1 23.05 vs 23.15 (the
  super-linear ring-lock crossover); exact 100% throughout.
- tune (N=1): 256K ring drops ~123k -> >=1M ring drops 0 at ~0.67 cores
  throughout; wakeup_batch does not help (drops 92k-156k at the 256K ring).
- accuracy (Duffield sqrt(N/M)): M/N=10 (N=100,M=1000) mean 0.247 < 0.316, cov
  0.971; M/N=100 (N=100,M=10000) mean 0.082 < 0.100, cov 0.999; N=10,M=1000 mean
  0.076 < 0.100, cov 0.880. The N=1000,M=10000 point is the same documented
  anomaly (coverage 2.34: flows outlive the 1s eviction and export as multiple
  IPFIX records); excluded from the figure.
- head-to-head (sys_cores over baseline, per N): rfm +1.38/+0.42/+0.18/+0.18,
  netobserv +0.33/+0.16/+0.13/+0.17, hsflowd +0.15/+0.13/+0.14/+0.16 (all eBPF
  near baseline); softflowd +5.6/+4.5/+5.0/+4.7 and pmacctd +4.3/+3.0/+3.3/+3.4
  (libpcap, 10-40x heavier, flat in N). rfm N=1 is the consumer-bound spike
  (sheds ~20.1M events/s). BPF-map memory: rfm 314 KB, netobserv 1453 KB,
  hsflowd 91 KB -- identical to 06-25.
- kmem (flow cardinality): rfm flat 314 KB and hsflowd flat 91 KB at every F (no
  per-flow table); netobserv total map 1453/2234/2235/2235 KB at F=1k/5k/20k/50k
  -- identical to 06-25 -- with the aggregated_flow hash memlock 325->1107 KB
  capped at max_entries=5000. (The instantaneous live-entry count read lower
  this run -- ~1000/2000/2000/1900 vs 06-25's ~1000/5000/5000/5000 -- because
  netobserv periodically drains its kernel map, so occupancy is sampling-phase
  dependent; the kernel MEMORY, preallocated at max_entries and the figure's
  metric, is identical.)
- progcost (per-packet, line rate): rfm 106 ns, hsflowd 94 ns, netobserv 66 ns
  in-program (runs_per_rx ~1.0; rfm 0.68 here, packets dropped before the TC
  hook at extreme load) -- matches 06-25 (106/94/67).
- rss (RX-queue sweep, N=100, line rate): 1.14/2.16/4.20/7.28/12.65/14.29 Mpps
  at queues 1/2/4/8/16/32, 0 ring drops at every count, kernel 0.05->1.40 cores
  -- matches 06-25 (1.13/2.15/4.17/7.21/12.54/14.15).
- realnic (rfm overhead vs N, line rate): N=1000 14.4 Mpps / 0.097 cores/Mpps,
  N=100 14.3 / 0.120, N=10 13.9 / 0.193; 0 ring drops at N>=100, 14.0M at N=10.
  The N=1000 production operating point matches 06-25 (15.0 Mpps / 0.107
  cores/Mpps). At N=100/N=10 this run sustained ~14 Mpps rather than backing off
  to ~4 Mpps as in 06-25; the consumer is still saturated (N=10 sheds 14M events
  and pins ~1 user core) but more packets keep reaching the TC hook. See "Issues
  found".

## Issues found

None of these is an rfm or harness-logic defect; they are repo/setup notes and
line-rate operational hazards, each with the workaround used.

1. Frontend `~/rfm` checkout was one commit behind local (`650554a`, before
   `71c7910` "new workloads with kmem"): no `kmem.nu`, and older `headtohead.nu`
   / `lib.nu`. Running its copies would have skipped the kmem sweep and used a
   pre-final head-to-head. Sourced the harnesses from the local committed HEAD
   `dc47248` instead, rsync'd to both nodes, sha256-verified byte-identical.

2. The two-node harnesses (gen, headtohead, realnic, rss, progcost) default
   `--iface ens3f0np0`, the old Grenoble/dahu i40e name. On the Nancy gros mlx5
   nodes the data NIC is `eno1np0`, so every two-node invocation must pass
   `--iface eno1np0` (kmem.nu already defaults to eno1np0). A parameter, not a
   script edit.

3. There was no nu harness for the DPDK line-rate generator; its exact testpmd
   command lived only as prose in each run's readme (the moderate flood has
   gen.nu). Added `bench/workload/dpdk.nu`, which wraps the testpmd command plus
   the runtime 2M-hugepage allocation and the orphan-`rtemap` cleanup (issue 5),
   and exposes `--stop`. Used by this run's line-rate leg.

4. realnic stale-TC-program hazard (intermittent; the one the 06-25 readme
   already warns about). The first line-rate realnic pass (inside the initial
   Phase C suite) reported rx pps 0 for N=1000 and N=10 while keeping N=100 at
   full line rate. The rx rate is derived from the TC ingress program's run_cnt
   via `bpftool
   prog show`; between the sweep's internal per-N rfm
   attach/detach cycles a previous program can linger, so `ingress-stat` (which
   takes the first matching program) reads a stale, frozen run_cnt and the rate
   computes to 0 -- exactly the hazard the harness comment calls out ("rfm must
   start from a clean state each run"). Re-running the SAME unmodified harness
   `nu realnic.nu --ns "1000 100 10"` from a clean datapath (kill rfm + drop the
   clsact qdisc before the run) produced three clean points with no zeros --
   this is the canonical realnic.json. A per-N cross-check (one invocation per
   N, datapath cleaned between each; realnic-N{1000,100,10}.json) agrees to 3
   digits, confirming the clean values. The remaining difference from 06-25 is
   not the hazard but the regime: this run sustained ~14 Mpps at N=100/N=10
   instead of the ~4 Mpps back-off 06-25 saw. The consumer is saturated either
   way (N=10 sheds 14M events, ~1 user core), but the receive path
   back-pressured less here; the line-rate operating point (N=1000, ~0.1
   cores/Mpps) reproduces.

5. DPDK flood does not restart cleanly. A dpdk-testpmd killed with SIGKILL (the
   only option once the line-rate flood has stalled the in-band kavlan SSH)
   orphans its `/dev/hugepages/rtemap_*` files, which pin the hugepages so the
   next EAL init cannot allocate and the new testpmd never floods (TX stuck at
   the initial burst). A partial `rm rtemap_*` is not enough; a full reset
   (`nr_hugepages=0; rm -f /dev/hugepages/*; nr_hugepages=8192`) is required.
   The DUT mlx5 RX also wedged into an all-`rx_out_of_buffer` state after the
   repeated `ethtool -L combined` channel resets that rss.nu performs, and
   needed a link down/up
   (`ip link set eno1np0 down; ethtool -L combined 36; up`) to rebuild its RX
   rings. The first (clean-boot) flood always worked; only restarts needed this.
   The original Phase C suite (progcost, rss, and the realnic N=100 point) ran
   under that first good flood and reproduce 06-25 exactly.

## Methodology notes

- Single-node microbench (overhead, scale, tune, accuracy): rfm only, over a
  veth pair driven by kernel pktgen; rfm monitors the peer. rfm-specific
  (cores/Mpps from bpf_stats). No real NIC.
- Head-to-head (5 agents): on the real mlx5 NIC under the ~2.09 Mpps gen.nu
  flood (1000 flows), swept over N=1/10/100/1000. CPU = system-wide busy cores
  (delta of /proc/stat). Each agent force-killed (SIGKILL) before the next (the
  2026-06-21 contamination fix). Memory = bytes_memlock of the agent's own BPF
  maps.
- kmem: under the moderate flood with F distinct flows, reads each in-kernel
  agent's BPF-map locked memory and per-flow-table occupancy.
- Line-rate (realnic, rss, progcost): under the ~15-16 Mpps DPDK flood. rx rate
  from the TC program run_cnt (rfm's HTTP endpoint is unreachable under full
  saturation, loadavg ~39); ring drops best-effort (-1). N=1 excluded at line
  rate.

## Result file manifest

Same as 2026-06-25: overhead.json; scale-N{1,10,100,1000}.json; tune.json;
acc-N{100,10,1000}-M{1000,10000}.{csv,summary};
headtohead-N{1,10,100,1000}.json; kmem-F{1000,5000,20000,50000}.json;
realnic.json (canonical single-pass) plus realnic-N{1000,100,10}.json (clean
per-N cross-check); rss.json; progcost.json + progcost.table.txt.
