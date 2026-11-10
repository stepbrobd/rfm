# RFM tuning pass, harness dry run and production window, 2026-11-09 (Grid'5000 Louvain, spirou, routed KaVLAN)

Produced by `bench/workload/measure.nu` (one window of one monitor, one JSON
line), `bench/workload/gen.nu` (pktgen), `bench/workload/campaign.sh` (the
driver, run on the frontend), `bench/workload/control.nu` and the progbench
harnesses, at the commits `e65dc5a` to `9d05bad`. The production window comes
from the read-only scripts in `production/`. The night run of job 20519 is
added to this directory when it ends.

## Testbed

- Site and cluster: Grid'5000 Louvain, `spirou`: Lenovo SR630 V2, 2x Xeon Gold
  5318Y (48 cores, 96 threads, possible = online = 0-95), 256 GiB, ConnectX-6
  Dx 100GbE (`mlx5_core`, firmware 22.31.1014) on NUMA node 0 (CPUs 0-23,
  48-71), 63 combined channels, `ens1f0np0` in the KaVLAN, `ens1f1np1` on the
  production network. Both nodes on one MSN3700C.
- OAR job 20518, 13:22 to 16:24, spirou-7 and spirou-8 in routed KaVLAN 4
  (10.48.0.0/18), through `~/rfm-kavlan-deploy.sh` on the frontend.
- Image: the rfm master Grid'5000 image of 2026-11-09 (nixpkgs `0dea955`), rfm
  2026.1105.0 (agent code equal to `v2026.1105.0`), NetObserv eBPF agent 2.0.2
  with direct FLP, hsflowd 2.1.26, pmacctd 1.7.9, softflowd 1.1.1.
- Turbo on, C-states at their default with C6 enabled, governor `performance`,
  irqbalance off, rx and tx rings 8192, mlx5 IRQ affinity at the driver's
  default. `d1/inventory-*.txt` holds the full inventory per node.
- A blackhole route for 10.0.0.0/8 on both nodes, checked with
  `ip route get 10.200.0.1` before any flood, so a spoofed source never leaves
  over the production route.

## Roles

- spirou-7, 10.48.0.7, `e8:eb:d3:fd:ce:ac`: DUT, every monitor runs here.
- spirou-8, 10.48.0.8, `e8:eb:d3:fd:cf:0c`, PCI `0000:4b:00.0`: pktgen and
  iperf3 generator.

## Tables

`measure_tables.py` turns `measure.nu` JSON lines into the tables of this
directory and of `../2026-11-10/`, one per cell with every variant's mean and
spread over its rounds, busy cores over the same round's empty baseline, and
the counts against the wire where the window kept them:

```
python3 -I measure_tables.py night/res/b3.jsonl
```

The deploy logs of the three jobs are `d1/kadeploy-20518.log`,
`night/kadeploy-20519.log` and `../2026-11-10/job20520/kadeploy-20520.log`.

## T0, the tuning pass (`t0/`)

60 byte frames over 1000 flows, one pktgen thread (2.62 Mpps) or four (8.9
Mpps), spread over the 63 queues. One 30 s window per cell after a 10 s warmup,
ns per packet from an 8 s `bpf_stats` window. The drivers are `t0/t0.sh`,
`t0/t0b.sh` and `t0/t0c.sh`, each a loop of:

```
nu /root/workload/gen.nu --iface ens1f0np0 --dst 10.48.0.7 --dstmac e8:eb:d3:fd:ce:ac --flows 1000 --count 4000000000 --threads <1|4>
nu /root/workload/measure.nu --warmup 10 --secs 30 --stat-secs 8 --out /root/res/t0.jsonl --agent <rfm|netobserv|hsflowd|none> --n <N> --rfm-bpf '<toml lines>' --label <cell>
```

| rfm configuration at N                         | ns per packet, 2.6 Mpps | ns per packet, 8.9 Mpps | agent cores, 2.6 / 8.9 Mpps | BPF maps  | RSS    |
| ---------------------------------------------- | ----------------------- | ----------------------- | --------------------------- | --------- | ------ |
| N=100, defaults (stage 1, 64 KiB rings)        | 82.0                    | 43.0                    | 0.006 / 0.019               | 7857 KB   | 42 MB  |
| N=100, stage 16                                | 67.2                    | 39.7                    | 0.006 / 0.015               | 8027 KB   | 42 MB  |
| N=100, stage 32                                | 68.1                    | 40.3                    | 0.007 / 0.015               | 8027 KB   | 42 MB  |
| N=100, stage 32, `iface_slots` 1, 16 KiB rings | 65.7                    |                         | 0.011                       | 3131 KB   | 33 MB  |
| N=100, 4 KiB rings, stage 1                    | 79.0                    |                         | 0.025                       | 2075 KB   | 22 MB  |
| N=100, `sampled_only`, stage 1                 | 54.6                    | 29.9                    | 0.006 / 0.021               | 7380 KB   | 42 MB  |
| N=100, `sampled_only`, stage 16                | 45.7                    |                         | 0.007                       | 7550 KB   | 42 MB  |
| N=100, `sampled_only`, stage 32, 16 KiB rings  | 46.5                    |                         | 0.011                       | 2924 KB   | 33 MB  |
| N=100, `GOGC=400`                              | 81.5                    |                         | 0.006                       | 7857 KB   | 43 MB  |
| N=10, stage 1                                  | 124.4                   |                         | 0.043                       | 7857 KB   | 42 MB  |
| N=10, stage 16                                 | 87.2                    | 52.7                    | 0.035 / 0.103               | 8027 KB   | 43 MB  |
| N=10, stage 32, `iface_slots` 1, 16 KiB rings  | 82.3                    | 51.5                    | 0.044 / 0.121               | 3131 KB   | 33 MB  |
| N=10, `sampled_only`, stage 32, 16 KiB rings   |                         | 40.1                    | 0.123                       | 2924 KB   | 33 MB  |
| N=1, stage 1, 256 KiB rings                    | 233.3                   |                         | 0.204                       | 26361 KB  | 78 MB  |
| N=1, stage 1, 1 MiB rings                      | 233.7                   | 172.1                   | 0.185 / 0.763               | 100377 KB | 222 MB |
| N=1, stage 32, 256 KiB rings                   | 140.0                   | 98.7                    | 0.158 / 0.519               | 26531 KB  | 78 MB  |
| N=1, stage 32, 1 MiB rings                     | 136.2                   | 94.1                    | 0.141 / 0.507               | 100547 KB | 222 MB |
| NetObserv 2.0.2, N=100                         | 67.9                    | 38.8                    | 0.006 / 0.005               | 378 KB    | 62 MB  |
| NetObserv 2.0.2, N=10                          |                         | 63.1                    | 0.005                       | 378 KB    | 62 MB  |
| hsflowd, N=100                                 | 128.7                   |                         | 0.094                       | 94 KB     | 5 MB   |

No cell dropped a ring event or a frame at the port. Busy cores of the whole
machine read 5.64 and 5.68 with nothing attached at 2.6 Mpps and 11.95 at 8.8
Mpps, and single windows scattered by about 0.3 cores, too much to rank the
eBPF monitors on busy cores from one window. Counted in kernel and user time
together, exact rfm ties NetObserv (0.183 against 0.184 cores at N=100, 0.58
against 0.57 at N=10 and 8.9 Mpps) and `sampled_only` costs 28% less at N=100.
The configurations picked for the night, the defaults of `campaign.sh`:

| row      | `[agent.bpf]` lines                                           |
| -------- | ------------------------------------------------------------- |
| exact    | `stage_events=32`, `iface_slots=1`, `ring_buf_size=16384`     |
| sampled  | `sampled_only=true`, `stage_events=32`, `ring_buf_size=16384` |
| N=1      | `stage_events=32`, `iface_slots=1` (derived 256 KiB rings)    |
| memory   | `stage_events=32`, `iface_slots=1`, `ring_buf_size=4096`      |
| defaults | none                                                          |

## D1, the harness dry run (`d1/`)

`DRY=1 campaign.sh 20518 ~/rfm-d1 'setup b5 b1 b3 b4 b7 b2 b12 b8 b9 b10 b11'`
on the frontend, from 14:37 to 15:44: one round, one trial, 3 to 4 s windows,
so the numbers check the harness and are not results. `d1/campaign.log` is the
driver's log with every remote command, `d1/res/` the per phase JSON lines and
stderr as copied from the DUT (with `dry.jsonl` and `dryacc.jsonl`, the first smoke checks of `measure.nu` that afternoon), `d1/res/t2.jsonl` the two paced B2 points
checked by hand with `d1/t2.sh` after the driver stopped in B9 (a progbench in
situ stall), so B10 and B11 did not run in D1. What changed after it: B7 uses
`gen.nu --queue-xmit` (pktgen's default `start_xmit` skips TC egress), the B2
points are paced so they reach 1 frame per skb, the progbench in situ runs use
N of 1000 and more under `timeout 900`, and `quiet()` kills a stalled
progbench. Read as checks only: under GRO NetObserv and hsflowd reported 2.76
and 2.70% of the received wire packets and rfm 1.0006, under TSO 2.19 and
2.22% of the sent ones.

## Production window (`production/`)

15 nodes of the maintainer's fleet on rfm 2026.1105.0 at N=10, read only, from
2026-11-09T15:21:42Z to 17:32:59Z:

```
bash production/run.sh prod
```

- `vm.py` reads each node's VictoriaMetrics over the window since the running
  rfm version was first deployed (4.0 days), single series counters and gauges
  only, then compares `increase()` with chained deltas (`*.bias.json`).
- `scrape.py` chains direct `/metrics` deltas every 60 s for 7800 s
  (`*.jsonl`).
- `flowsize.py` snapshots the flow table every 20 s for 7200 s. Flow keys are
  hashed in memory and never written. `flowsize_hist.json` holds, per node, the
  number of flow records and their estimated packets per count of samples,
  exact up to 100 samples, then in powers of two. The per flow file (92 MB) is
  not archived, so `analyze.py` reruns from this directory without its last
  section, whose output is in `tables.md`.
- `analyze.py` writes `tables.md` from all of the above, `window.md` is its
  first table, `maps.txt` the BPF map memory per node from
  `/proc/<pid>/fdinfo`, deduplicated by map id.

Per node rollups by peer ASN and city (the first scrape's raw text) are left
out on purpose.

Main figures: median RSS 69 MB and median CPU 0.35% of a core, no forced
evictions or folded flows, 556 ring drops on one node (butte) and none
elsewhere, estimated over exact packets 0.9961 to 1.0047 per node, while
`increase()` over the churning per flow rollups reads as low as 0.921. Flows
with 10 or more samples carry 99.8% of the estimated packets. BPF map memory is
278 to 835 KB where possible equals online CPUs and 2.7 to 10.4 MB on VMs that
advertise 32 to 128 possible CPUs, since rfm creates one ring per possible CPU.

## Night run (`night/`)

OAR job 20519, spirou-7 (DUT) and spirou-8 (generator) in KaVLAN 4, from 19:00
on 2026-11-09, on the same image and settings as above (rfm 2026.1105.0). The
driver ran from a frozen copy of the harness at `9d05bad`:

```
SRC=~/rfm-night-src campaign.sh 20519 ~/rfm-night
```

with the default phases `setup b5 b1 b3 b4 b7 b2 b12 b8 b9 b10 b11 more more2`
and the night configurations of `campaign.sh`. Every phase finished, at 03:05,
and no `measure.nu` call failed. `night/campaign.log` holds every remote
command with its time, `night/res/` the JSON lines and logs per phase.

The base N100 and N10 cells of rounds 4 and 5 in `night/res/b3.jsonl`, 32
windows labelled `base N100 r4`, `base N100 r5`, `base N10 r4` and
`base N10 r5`, ran with the iperf3 stream of the last B1 cell of the `more`
phase still up, which held pktgen at 1.2 to 1.3 Mpps in place of 2.63. They
are not results and are left out of every table. The `more2` cells and
rounds 1 to 3 are clean. `f91816d` stops the stream in the harness.
