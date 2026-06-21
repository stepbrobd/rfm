# RFM Benchmark Run 2026-06-21 (Grid'5000 Grenoble, dahu, routed KaVLAN)

Produced by bench/workload/*.nu on the nodes below. See *.json files in this
directory.

## Testbed

- Site/cluster: Grid'5000 Grenoble, cluster `dahu`.
- Nodes: 2x dahu (2x Xeon Gold 6130, 32c/64t, 2 NUMA, 188 GB; Intel X710 10GbE
  SFP+ i40e). Single usable data NIC `ens3f0np0` per node.
- Isolation: routed KaVLAN, VLAN id 4, subnet 10.4.0.0/18. Data NICs are off the
  production net, so node-to-node floods stay in the vlan.
- OAR job: 2901999 (oarsub -t deploy, {type='kavlan'}/vlan=1 + dahu/host=2,
  walltime 6h). Deployed with kadeploy3 (success on both nodes, ~177s).
- Image: ~/g5k-image/nixos-x86_64-linux (the bench base, NixOS 26.11
  20260619.d4fea6b), kernel 6.18.35. Agents baked in: rfm, netobserv-ebpf-agent
  v1.11.5, hsflowd 2.1.26-1 (mod_epcap.so + mod_psample.so), goflow2, nu,
  ethtool.

## Roles

- DUT (device under test): dahu-7, 10.4.1.7, MAC 3c:fd:fe:54:79:20. Runs rfm and
  the baseline agents; all overhead/accuracy/scale/realnic/rss/ head-to-head
  sweeps run here.
- Generator: dahu-20, 10.4.1.20, MAC 3c:fd:fe:54:c8:38. Kernel pktgen flood via
  bench/workload/gen.nu (no DPDK/TRex available).

Node-to-node in the vlan: ping 0% loss, ~0.25 ms RTT (L2 direct).

## Methodology notes

- Single-node microbench (overhead, accuracy, tune, scale): kernel pktgen over a
  veth pair, rfm monitors the peer; ground truth = pktgen send counts + rfm
  per-CPU interface counters (exact).
- Two-node real-NIC (realnic, rss, headtohead): gen.nu floods dahu-7 over the
  real i40e NIC (64 RX queues default). Offered load ~2.1-2.2 Mpps of 64B,
  UDPSRC over 1000 flows (single pktgen TX thread; more threads gave less, skb
  rebuild bound -- no DPDK so this is the honest ceiling, not 14.88 Mpps line
  rate). realnic runs descending N (N=1 last) so the N=1 softirq storm does not
  starve the userspace sweep driver. rss resets RX queue count via ethtool -L.
- Fair cost metric in head-to-head = system-wide busy cores (delta of
  /proc/stat: NIC softirq + capture + userspace), matched 1-in-N across agents.

## Result file manifest

- overhead.json single-node: datapath overhead vs N (veth, 5M pkts/N)
- acc-N100-M1000.csv single-node: per-flow accuracy, M/N=10
- acc-N100-M10000.csv single-node: per-flow accuracy, M/N=100
- tune.json single-node: ring_buf_size / wakeup_batch sweep at N=1
- scale-N100.json single-node: multi-core scaling, N=100 (linear regime)
- scale-N1.json single-node: multi-core scaling, N=1 (contention regime)
- realnic.json two-node real NIC: overhead vs N at ~2.1 Mpps
- rss.json two-node real NIC: RSS RX-queue sweep
- headtohead.json two-node real NIC: rfm vs pmacctd/softflowd/netobserv/hsflowd
- progcost.json two-node real NIC: per-packet eBPF program cost (runs_per_rx,
  avg ns)
- progcost.txt human-readable per-packet cost summary + interpretation

## Headline results (see the json files for the full sweeps)

Single-node (veth + pktgen, ~0.95 Mpps single thread):

- overhead: exact per-CPU counters 100.000% at every N; ring drops only at N=1
  (82k/5M); kernel 55.6 ns/pkt (N=1024) -> 288 ns/pkt (N=1); userspace 0.009 ->
  0.726 cores.
- accuracy: per-flow mean rel-err under the Duffield sqrt(N/M) bound -- M/N=10
  -> 0.245 (coverage 0.76), M/N=100 -> 0.087 (coverage 0.96).
- tune: ring_buf_size 256K -> 4M eliminates the N=1 drops at ~no CPU cost.
- scale (exact counters 100% throughout): N=100 scales linearly 1->32 cores to
  23.55 Mpps (kernel 1.03 c, 0 drops); N=1 plateaus ~2.50 Mpps with kernel cores
  super-linear 0.12 -> 26.2 c and drops 0 -> 55M. Crossover ~9.4x at 32 cores.

Two-node real i40e NIC (offered ~2.1-2.2 Mpps of 64B, 1000 flows):

- realnic (overhead vs N): N=100 -> 120 ns/pkt, 0 drops, 0.17 cores/Mpps; N=1 ->
  1095 ns/pkt, 20.6M drops, 1.58 cores/Mpps (~9.5x N=100).
- rss: 1 RX queue caps ~0.84 Mpps; at N=100 0 drops at every queue count (kernel
  0.05 -> 0.33 c); at N=1 kernel cores climb 0.54 -> 2.31 c as queues 2 -> 64.
- head-to-head (matched 1/100, system-wide busy cores over a 6.0-core softirq
  baseline): rfm +0.60 (0 drops); hsflowd(epcap) +15.2; softflowd +15.7;
  netobserv +17.0 (Sampling:100 confirmed); pmacctd +21.9 (libpcap). 25-37x gap.
- progcost: every agent's TC/TCX program runs per-packet (runs_per_rx=1.0); rfm
  117 ns, hsflowd 98 ns, netobserv 72 ns in-program. rfm's low total cost is
  from sampling first + holding no per-flow kernel state, not from skipping
  packets.

Caveat: generator is kernel pktgen (no DPDK/TRex), so the offered load ~2.2 Mpps
is the honest ceiling, not 64B line rate (14.88 Mpps); no RFC2544 binary-search
MLFR and no cgroup memory.peak were captured in this run. dahu has no wattmeter,
so no energy numbers.
