# RFM per-program cost of the optimization variants, XDP, sampling accuracy and offloads, 2026-11-03 (Grid'5000 Nancy, gros, routed KaVLAN)

Produced by `bench/progbench` (Go, `BPF_PROG_TEST_RUN`, an in situ attach mode
and an accuracy mode), `bench/progbench/build.nu` (objects),
`bench/workload/progbench.nu`, `bench/workload/progbench_insitu.nu`,
`bench/workload/progbench_accuracy.nu`, `bench/workload/progbench_offload.nu`,
`bench/workload/gen.nu` and `bench/workload/progcost.nu`. The variants are
compile time switches in `bench/progbench/bpf/rfm_variants.c`, a bench-only copy
of `bpf/rfm_tc.c`, never loaded by the agent.

## Testbed

- Site and cluster: Grid'5000 Nancy, `gros`: Xeon Gold 5220 (18c/36t, Cascade
  Lake), 96 GB, Mellanox ConnectX-4 Lx 25GbE (`mlx5`), `eno1np0` in the KaVLAN,
  `eno2np1` on the production network.
- OAR job 7002141
  (`oarsub -t deploy -l "{type='kavlan'}/vlan=1+{cluster='gros'}/host=2,walltime=3:0:0" ~/kavlan-deploy.sh`),
  KaVLAN 4 (10.16.0.0/18).
- Image `~/g5k-image/nixos-x86_64-linux` (NixOS 26.11 20260619.d4fea6b), kernel
  6.18.35. Agents in the image: rfm of 2026-06-19 (before the wire accounting
  fix), netobserv-ebpf-agent v1.11.5, hsflowd 2.1.26-1.
- Governor set to `performance` on every CPU of both nodes before the runs,
  turbo left on (`no_turbo` 0), `kernel.bpf_stats_enabled` 0 except while the in
  situ binary or progcost holds it.

## Roles

- gros-63, 10.16.0.63, `eno1np0` 98:03:9b:b0:a7:66: test runs, then DUT for the
  in situ, progcost and offload runs.
- gros-68, 10.16.0.68: test runs, then the pktgen generator and the iperf3
  client, and the N=10 test runs and the accuracy runs on CPU 12 while it
  generated.

## Objects

Built on the dev box with `nu bench/progbench/build.nu --out <dir>` (clang
21.1.8, libbpf headers from the dev shell). `agent_v1` is `bpf/rfm_tc.c` at
`-mcpu=v1`, the same ingress disassembly as the committed `probe/rfm_bpfel.o`,
`agent_v3` and `agent_v4` the same source at v3 and v4. `var_mod_hash_v1` is the
variants file with every knob at the agent's behavior, it measures within 1 ns
of `agent_v1`, so the variants compare against today's agent.

| label                                            | change against the agent                                                                              |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| empty                                            | returns at once, the floor of a run                                                                   |
| agent_v3, agent_v4                               | ISA v3 or v4 (O11)                                                                                    |
| thresh_hash                                      | v3, threshold draw (O3)                                                                               |
| mod_array                                        | v3, per-CPU array counter at a slot (O1)                                                              |
| thresh_array                                     | v3, O1 and O3                                                                                         |
| skip_array                                       | v3, O1, skip count in the counter slot                                                                |
| thresh_array_lazy_nowake, skip_array_lazy_nowake | the above plus O12 (egress header parse only when gso_segs is 0) and O7 (always `BPF_RB_NO_WAKEUP`)   |
| nocounter_thresh                                 | v3, no counter, threshold draw after the parse                                                        |
| sampled_mod, sampled_thresh, sampled_skip        | sampled profile: the draw first, no counter, modulo, threshold or skip count                          |
| sampled_thresh_lazy_nowake                       | sampled profile with O12 and O7                                                                       |
| xdp_empty                                        | native XDP ingress program that returns at once, TCX egress empty                                     |
| xdp_skip_array                                   | ingress as native XDP, exact profile with O1, the skip count and O7, egress as skip_array_lazy_nowake |

## Commands

Test runs, both nodes, CPU 2, 7 trials per point, each on a fresh load,
2,000,000 runs per trial (400,000 at N=1):

```
nu progbench.nu --dir progbench
```

N=10 on gros-68 during the flood, CPU 12:

```
nu progbench.nu --dir progbench --ns "10" --cpu 12 --labels "empty agent_v1 agent_v3 thresh_hash mod_array thresh_array skip_array thresh_array_lazy_nowake skip_array_lazy_nowake nocounter_thresh sampled_mod sampled_thresh sampled_skip sampled_thresh_lazy_nowake"
```

Accuracy on gros-68 during the flood, CPU 12, 1000 flows, both orders:

```
nu progbench_accuracy.nu --dir progbench --cpu 12
nu progbench_accuracy.nu --dir progbench --cpu 12 --order burst
```

Flood from gros-68, 4 pktgen threads, 60 B UDP over 1000 source ports, about
1.92 Mpps at the DUT. Every skb is rebuilt (`clone_skb 0`), which caps the
generator near 1.9 Mpps whatever the thread count (12 threads gave 1.78 Mpps),
and the 600 Mbit/s per thread cap never binds:

```
nu gen.nu --iface eno1np0 --dst 10.16.0.63 --dstmac 98:03:9b:b0:a7:66 --threads 4 --size 60 --count 4000000000 --flows 1000 --rate 600
```

Higher load, 8 threads, each skb sent 16 times and 8 packets per doorbell, about
5.5 Mpps at the DUT with no `rx_out_of_buffer` or `rx_discards_phy`:

```
nu gen.nu --iface eno1np0 --dst 10.16.0.63 --dstmac 98:03:9b:b0:a7:66 --threads 8 --size 60 --count 4000000000 --flows 1000 --clone 16 --burst 8
```

In situ on gros-63, 5 s warmup, 20 s window, shuffled order per round. N=100
over every label, 3 rounds, then N=10 and the higher load over subsets, 2
rounds:

```
nu progbench_insitu.nu --dir progbench --iface eno1np0 --n 100 --rounds 3
nu progbench_insitu.nu --dir progbench --iface eno1np0 --n 10 --rounds 2 --out /tmp/insitu_n10.jsonl --labels "none empty agent_v3 thresh_array_lazy_nowake skip_array_lazy_nowake sampled_thresh_lazy_nowake sampled_skip xdp_skip_array"
nu progbench_insitu.nu --dir progbench --iface eno1np0 --n 100 --rounds 2 --out /tmp/insitu_n100_high.jsonl --labels "none empty agent_v1 agent_v3 skip_array_lazy_nowake sampled_skip xdp_empty xdp_skip_array"
nu progbench_insitu.nu --dir progbench --iface eno1np0 --n 1000 --rounds 2 --out /tmp/insitu_n1000_high.jsonl --labels "none empty agent_v1 skip_array_lazy_nowake sampled_skip"
nu progbench_insitu.nu --dir progbench --iface eno1np0 --n 10000 --rounds 2 --out /tmp/insitu_n10000_high.jsonl --labels "none empty agent_v1 skip_array_lazy_nowake sampled_skip"
```

progcost on gros-63 under the 1.92 Mpps flood, three times:

```
nu progcost.nu --iface eno1np0 --secs 20 --n 100
```

Offloads on gros-63 during a TCP bulk transfer from gros-68, GRO on then off, 2
rounds each, 3 s warmup, 15 s window:

```
iperf3 -s -D                                   # gros-63
iperf3 -c 10.16.0.63 -P 8 -t 900 -i 10         # gros-68
nu progbench_offload.nu --dir progbench --iface eno1np0
```

The tables come from the JSON lines. A test run figure is the median over trials
of `wall_ns_runs` (`ns_runs` for XDP, whose wall clock carries the test run
loop), averaged over the two nodes. An in situ figure is the mean over rounds of
`ingress_ns_per_run`, and of `busy_cores` less the mean of the `none` rounds.
Count over wire is the sum of `rfm_rx_packets` over the sum of
`wire_rx_packets`, bytes over wire the sum of `rfm_rx_bytes` over the sum of
`wire_rx_bytes` less 4 bytes of FCS per wire packet. An accuracy ratio is
`std_rel_err` over `bernoulli_std`.

## Results

Test runs, ns per run, wall clock, the mean of the two nodes' medians, IPv4 TCP
ingress unless stated, floor 7.4 ns:

| label                  | N=100 | N=100 non-IP | N=100 GSO in | N=100 GSO out | N=1  | N=10 (gros-68 under load, floor 8.5) |
| ---------------------- | ----- | ------------ | ------------ | ------------- | ---- | ------------------------------------ |
| agent_v1               | 36.8  | 25.7         | 45.4         | 44.9          | 97.1 | 47.3                                 |
| agent_v3               | 31.8  | 24.8         | 39.8         | 39.5          | 93.6 | 41.7                                 |
| thresh_hash            | 30.4  | 25.1         | 37.6         | 37.3          | 91.9 | 39.2                                 |
| mod_array              | 24.1  | 14.8         | 32.1         | 31.8          | 80.8 | 33.1                                 |
| thresh_array           | 20.6  | 14.3         | 28.9         | 29.1          | 81.7 | 29.0                                 |
| skip_array             | 16.1  | 14.9         | 23.8         | 23.7          | 78.3 | 24.9                                 |
| skip_array_lazy_nowake | 15.7  | 14.7         | 23.7         | 16.6          | 62.4 | 23.5                                 |
| nocounter_thresh       | 18.0  | 12.1         | 26.0         | 26.0          | 76.3 | 25.2                                 |
| sampled_mod            | 16.0  | 15.3         | 15.9         | 16.2          | 78.1 | 23.9                                 |
| sampled_thresh         | 14.4  | 13.9         | 14.4         | 14.4          | 76.9 | 21.8                                 |
| sampled_skip           | 10.2  | 9.8          | 10.5         | 10.2          | 73.9 | 18.6                                 |

In situ, gros-63, N=100, 1.92 Mpps offered, ingress ns per run from `bpf_stats`
(mean and sd of 3 rounds), busy cores over the 2.981 cores with nothing attached
(sd 0.010), and the object's exact ingress count over the mlx5 port counter:

| label                    | hook | ns per run | sd  | busy cores over none | sd    | ns per packet system wide | count over wire |
| ------------------------ | ---- | ---------- | --- | -------------------- | ----- | ------------------------- | --------------- |
| empty                    | tcx  | 18.2       | 0.0 | 0.069                | 0.005 | 36.4                      |                 |
| agent_v1                 | tcx  | 81.8       | 0.3 | 0.177                | 0.005 | 92.7                      | 0.99999         |
| agent_v3                 | tcx  | 72.6       | 0.6 | 0.168                | 0.020 | 87.9                      | 1.00002         |
| thresh_array             | tcx  | 52.0       | 0.7 | 0.140                | 0.010 | 72.9                      | 0.99999         |
| skip_array               | tcx  | 40.2       | 0.7 | 0.118                | 0.008 | 61.2                      | 1.00001         |
| thresh_array_lazy_nowake | tcx  | 51.7       | 0.9 | 0.134                | 0.016 | 69.6                      | 1.00001         |
| skip_array_lazy_nowake   | tcx  | 40.2       | 0.9 | 0.114                | 0.015 | 59.5                      | 1.00000         |
| nocounter_thresh         | tcx  | 43.7       | 0.4 | 0.123                | 0.013 | 64.3                      |                 |
| sampled_thresh           | tcx  | 37.0       | 0.2 | 0.116                | 0.009 | 60.4                      |                 |
| sampled_skip             | tcx  | 27.3       | 0.1 | 0.101                | 0.005 | 52.4                      |                 |
| xdp_empty                | xdp  | 25.5       | 0.2 | 0.055                | 0.009 | 28.7                      |                 |
| xdp_skip_array           | xdp  | 44.1       | 0.7 | 0.095                | 0.004 | 49.4                      | 0.99999         |

Every variant drained about 19,200 events/s with no ring drops.

In situ, N=10, 1.91 Mpps, 2 rounds, about 191,000 events/s, busy cores over the
2.973 with nothing attached:

| label                      | hook | ns per run | busy cores over none | sd    | ns per packet system wide |
| -------------------------- | ---- | ---------- | -------------------- | ----- | ------------------------- |
| empty                      | tcx  | 18.1       | 0.070                | 0.005 | 36.7                      |
| agent_v3                   | tcx  | 99.3       | 0.247                | 0.017 | 128.6                     |
| thresh_array_lazy_nowake   | tcx  | 75.6       | 0.195                | 0.010 | 102.0                     |
| skip_array_lazy_nowake     | tcx  | 68.3       | 0.170                | 0.008 | 88.9                      |
| sampled_skip               | tcx  | 58.0       | 0.171                | 0.010 | 89.5                      |
| sampled_thresh_lazy_nowake | tcx  | 60.4       | 0.160                | 0.002 | 83.7                      |
| xdp_skip_array             | xdp  | 75.3       | 0.155                | 0.012 | 80.9                      |

In situ, N=100, 5.48 Mpps offered (8 pktgen threads, `--clone 16 --burst 8`), 2
rounds, about 54,900 events/s with no ring drops, busy cores over the 8.522 with
nothing attached (sd 0.011). Exact counts within 4e-5 of the port counter:

| label                  | hook | ns per run | busy cores over none | sd    | ns per packet system wide |
| ---------------------- | ---- | ---------- | -------------------- | ----- | ------------------------- |
| empty                  | tcx  | 18.3       | 0.409                | 0.010 | 74.5                      |
| agent_v1               | tcx  | 83.0       | 0.857                | 0.054 | 155.8                     |
| agent_v3               | tcx  | 75.9       | 0.809                | 0.005 | 147.3                     |
| skip_array_lazy_nowake | tcx  | 40.5       | 0.579                | 0.032 | 105.5                     |
| sampled_skip           | tcx  | 27.2       | 0.478                | 0.009 | 87.2                      |
| xdp_empty              | xdp  | 23.7       | 0.266                | 0.004 | 48.4                      |
| xdp_skip_array         | xdp  | 46.3       | 0.455                | 0.023 | 83.0                      |

At this rate the hook itself separates TCX from XDP: the empty programs differ
by 0.143 cores, the optimized exact profiles by 0.124. Above the empty program
of its own hook, the exact profile costs 0.170 cores at TCX and 0.189 at XDP.

Sparser sampling at the same 5.5 Mpps, 2 rounds per N, busy cores over the run
with nothing attached (8.522, 8.609 and 8.630 cores). The program time gap
between the exact and the sampled profile stays near 14 ns per packet as N
grows, because only the event cost, which both profiles share, falls with N:

| label                  | N=100 ns | N=1000 ns | N=10000 ns | N=100 cores | N=1000 cores | N=10000 cores |
| ---------------------- | -------- | --------- | ---------- | ----------- | ------------ | ------------- |
| empty                  | 18.3     | 18.3      | 18.2       | 0.409       | 0.415        | 0.405         |
| agent_v1               | 83.0     | 79.4      | 79.2       | 0.857       | 0.787        | 0.759         |
| skip_array_lazy_nowake | 40.5     | 38.4      | 37.1       | 0.579       | 0.526        | 0.557         |
| sampled_skip           | 27.2     | 23.5      | 23.1       | 0.478       | 0.463        | 0.435         |

The busy cores gap between the two profiles reads 0.101, 0.063 and 0.122, 11 to
22 ns per packet system wide, with round to round sd up to 0.057 at N=1000.

Accuracy, 1000 flows of M packets, the standard deviation of the per-flow
relative error over the binomial standard deviation sqrt((N-1)/M) of Bernoulli
sampling at the same N. Round robin interleaves the flows, burst sends each flow
back to back. Bias within 0.011 (round robin) and 0.015 (burst) for every row,
coverage at least 0.999, no ring drops:

| label          | draw   | order       | N=100 M=1000 | N=100 M=10000 | N=10 M=100 | N=10 M=1000 |
| -------------- | ------ | ----------- | ------------ | ------------- | ---------- | ----------- |
| agent_v3       | modulo | round robin | 1.009        | 1.013         | 1.017      | 0.986       |
| thresh_array   | thresh | round robin | 1.027        | 0.962         | 1.024      | 0.991       |
| skip_array     | skip   | round robin | 1.000        | 1.002         | 0.979      | 1.017       |
| sampled_thresh | thresh | round robin | 1.004        | 0.973         | 1.042      | 1.018       |
| sampled_skip   | skip   | round robin | 0.987        | 1.005         | 0.980      | 1.039       |
| agent_v3       | modulo | burst       | 0.979        | 0.991         | 1.004      | 0.981       |
| thresh_array   | thresh | burst       | 1.007        | 0.959         | 1.034      | 1.017       |
| skip_array     | skip   | burst       | 0.608        | 0.573         | 0.587      | 0.591       |
| sampled_thresh | thresh | burst       | 1.021        | 1.000         | 0.973      | 0.996       |
| sampled_skip   | skip   | burst       | 0.622        | 0.557         | 0.592      | 0.592       |

The skip count spaces samples by a gap uniform on 1..2N-1, a renewal process
with mean N. A flow that holds every k-th packet of the aggregate has sample
count variance M p (1-p) + 2 sum over j from 1 to M-1 of (M-j) (p u(jk) - p^2),
with p = 1/N and u the renewal density of the gap, against M p (1-p) for
Bernoulli sampling. Computed exactly with M of 1000 at N=10 and 400 at N=100,
the standard deviation at k=1 (a burst) is 0.579 and 0.624 of binomial and tends
to 1/sqrt(3) = 0.577 as M grows, and over k from 1 to 4N the worst case is 1.034
of binomial at N=10 (k=19) and 1.003 at N=100 (k=199).

Offloads, iperf3 TCP from gros-68 with 8 streams at 23.1 Gbit/s, 2.03 Mpps on
the wire, N=100, 2 rounds per GRO setting. Ingress runs per wire packet is the
unit an skb counting monitor reports. Count and bytes over wire compare the
object's exact ingress counters with `rx_packets_phy` and with `rx_bytes_phy`
less the 4 byte FCS per frame. The driver count matched the port counter to 4
digits in every window:

| label                  | GRO | hook | ingress runs per wire packet | count over wire | bytes over wire | ingress ns per run | busy cores, round 1 / round 2 |
| ---------------------- | --- | ---- | ---------------------------- | --------------- | --------------- | ------------------ | ----------------------------- |
| agent_v3               | on  | tcx  | 0.0614                       | 1.00002         | 1.00002         | 137.1              | 1.879 / 2.123                 |
| skip_array_lazy_nowake | on  | tcx  | 0.0592                       | 0.99999         | 0.99999         | 76.0               | 1.860 / 2.113                 |
| xdp_skip_array         | on  | xdp  | 1.0000                       | 0.99999         | 0.99999         | 40.5               | 2.027 / 2.309                 |
| agent_v3               | off | tcx  | 1.0000                       | 0.99996         | 0.99996         | 74.5               | 8.786 / 8.678                 |
| skip_array_lazy_nowake | off | tcx  | 1.0000                       | 0.99998         | 0.99998         | 39.4               | 8.500 / 8.155                 |
| xdp_skip_array         | off | xdp  | 1.0000                       | 0.99998         | 0.99998         | 44.8               | 8.165 / 8.069                 |

With GRO on, an skb carried 22 wire packets in round 1 and 13 to 14 in round 2,
which means an skb counter would report 4.5 to 7.8 percent of the packets. The
TCX programs rebuild the wire count from `gso_segs` and the XDP program sees
every frame, and both match the port counter within 2e-5 in packets and bytes.
The cost differs: TCX runs once per GRO skb, XDP once per frame, and within each
round xdp_skip_array costs 0.167 and 0.196 more busy cores than
skip_array_lazy_nowake. With GRO off the stack costs about 6 more cores, every
hook runs once per frame, and xdp_skip_array costs 0.335 and 0.086 fewer cores
than skip_array_lazy_nowake, within the round to round spread of that column.
The sampled events (`events_ps`) count both directions, and the egress ACKs add
0.05 (GRO on) to 0.37 (GRO off) events per ingress wire packet at N=100.

progcost under the 1.92 Mpps flood, `bpf_stats` ns per run averaged over each
agent's TC programs, three runs: rfm of 2026-06-19 76, 74, 75, hsflowd epcap 61,
62, 61, netobserv 50, 50, 50.

## Caveats

- Test runs loop on one skb with warm caches and no `bpf_stats`, so they are a
  lower bound. The in situ runs include the `sched_clock()` pair of `bpf_stats`
  in every run, the empty program reads 18.1 ns there.
- `bpf_stats` ns per run does not compare across hooks. The XDP program is the
  first to touch the packet header and takes the cache miss the stack takes
  later under TCX, and xdp_skip_array reads 44.1 ns per run against 40.2 for
  skip_array_lazy_nowake while it costs fewer busy cores. Busy cores are the
  comparison between hooks.
- `progbench-insitu-n100-gros63-run1.jsonl` is a first N=100 run whose test
  consumer blocked in epoll without a deadline. In the always `BPF_RB_NO_WAKEUP`
  variants it never woke, and their busy cores left out the drain of about
  19,000 events/s. It is kept for the record and not used in the tables. The
  consumer now polls with a 50 ms deadline like the agent's 100 ms, and the
  rerun in `progbench-insitu-n100-gros63.jsonl` adds the XDP objects. Between
  the two runs the same objects moved by up to 0.02 busy cores, the noise floor
  of that column.
- progcost averages over all of an agent's TC programs and rounds to whole ns,
  the progbench in situ figure is the ingress program alone. Both read the same
  kernel counters on the same node and flood.
- The N=10 test runs and the accuracy runs ran beside the pktgen threads on the
  same node, which raised the test run floor from 7.4 to 8.5 ns. Accuracy does
  not depend on timing.
- The accuracy harness feeds the program from one CPU. On a real host a flow's
  samples come from the skip counter of the CPU that RSS steers it to, shared
  with the other flows of that queue, which lies between the two orders measured
  here.
