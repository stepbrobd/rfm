# RFM v2026.1109.0 for the IMC 2027 paper: the weekend campaign, two more NICs and the runs after it, 2026-11-13 to 2026-11-15 (Grid'5000 Louvain spirou, Nancy gros, Grenoble dahu)

Same harness family and rfm configurations as `../2026-11-10/`, on the image
of `v2026.1109.0` (rfm 2026.1109.0, kernel 7.3.1). Every testbed number of
the paper in mono `pkgs/imc27` comes from this directory through its
`figdata.py`, which names the source files of each table in the header of
every `data/*.dat`. The production numbers come from `../2026-11-09/production/`.

On spirou the DUT is spirou-7 and the generator spirou-8 in the routed KaVLAN
4, both with a ConnectX-6 Dx at 100 GbE (`ens1f0np0`, mlx5, 63 queues, rings
of 8192). `check.py` is the validity check over every `measure.nu` window of
the directory (failed calls, rounds per cell, traffic present, drops at the
port and in rfm's rings, the sampling rate each monitor applied), and skips
files that a later run copied again. Its report is `check.txt`. It flags 90
windows, all of them in `pm6/` and `weekend/`: packets dropped at the port
under pmacctd and softflowd, the last round of `pm6/`, which ran without
traffic, ring drops of 32 to 166 events in six windows of `b7`, and the one
window listed as invalid. No window of a later run is flagged.

## Runs

| directory            | job     | from             | to               | phases                                                         |
| -------------------- | ------- | ---------------- | ---------------- | -------------------------------------------------------------- |
| `pm6/`               | 20529   | 11-13 13:07      | 11-13 15:03      | pm6                                                            |
| `lpc/`               | 20529   | 11-13 15:03      | 11-13 15:21      | b1 with pmacctd and softflowd                                  |
| `cov/`               | 20529   | 11-13 15:32      | 11-13 15:47      | b4cov                                                          |
| `gros/`              | 7023876 | 11-13 14:17      | 11-13 15:59      | b1 b2 on 25 GbE                                                |
| `dahu/`              | 3169855 | 11-13 14:19      | 11-13 16:00      | b1 b2 on 10 GbE                                                |
| `weekend/`           | 20530   | 11-13 19:04      | 11-14 17:39      | b1 b12 b2 b4 b11 b3 b7 b5 b8 b9 pm sparse pm6 b4cov            |
| `weekend2/`          | 20530   | 11-14 17:39      | 11-14 21:24      | b13 pm3                                                        |
| `weekend3/`          | 20530   | 11-14 21:25      | 11-14 21:35      | b5 with later objects                                          |
| `ctl-dry/`, `ctl/`   | 20530   | 11-14 21:36      | 11-14 23:27      | b9s b13s ramp                                                  |
| `x-dry/`, `x/`       | 20530   | 11-14 23:27      | 11-15 05:03      | pm3s b1c b13p                                                  |
| `y-dry/`, `y/`       | 20530   | 11-15 05:04      | 11-15 06:49      | b8s b9s b9p env, turbo and C6 off                              |
| `z-dry/`, `z/`       | 20530   | 11-15 06:49      | 11-15 08:00      | pm6d, turbo and C6 off                                         |
| `m-dry/`, `m/`       | 20530   | 11-15 08:00      | 11-15 08:14      | b9m, turbo and C6 off                                          |

Each run of job 20530 was started by a wrapper on the louvain frontend that
waited for the run before it (`run.sh`, kept in the run's directory with its
`driver.out`, under `run/` from `ctl` on). From `ctl` on, a wrapper first
makes a pass with `DRY=1` (one round, windows of 3 s), drops a phase whose dry
pass shows a failing call or no rows, moves the dry rows away on the DUT and
then starts the real pass. The dry passes are kept as `*-dry/` and are no
measurement. The directories of the other jobs hold the same files where they
exist (`run.sh` of the runs a wrapper started, `driver.out`, the inventories),
and `gros/` and `dahu/` keep their result files at the top level. The deploy
log of each job is in its first directory: `pm6/rfm-kavlan-20529.log`,
`weekend/rfm-kavlan-20530.log`, `gros/rfm-kavlan-7023876.log` and
`dahu/rfm-kavlan-3169855.log`. Every result file was compared with its copy on
the frontend by checksum on 2026-11-15, after the last run.

`fetch` copies all of the DUT's `/root/res` after every phase, so the `res/`
of a later run on job 20530 holds the files of the earlier runs again, byte
for byte. The files that are new in a run are listed in its section.

The sections below name the harness commits as they stand after two rewrites of
the unpushed history: on 2026-11-15 the mode of `bench/workload/gap_error.py`
was amended into it, and on 2026-11-17 the messages were reworded with every
file left as it was. The runs were started from the earlier names, some of
which the comments in `ctl/run/run.sh`, `x/run/run.sh` and `z/run/run.sh` still
carry: `cfc81c8` for `490e676`, `a00f14c` for `af79f9d`, `ae17e9f` for
`ed49eed`, `89a7718` for `4eacd75`, `bfbea10` for `0534c72` and `a34ff33` for
`c31b7ff`, and for the last three runs `866b6c4` (`y`), `a3e1d42` (`z`) and
`a635f01` (`m`), which hold the same files as `1968050`, `b25a755` and
`aee2465` apart from that mode.

From 2026-11-13 13:11 to 2026-11-15 02:44 a helper on the frontend
(`~/rfm-weekend/live.sh`) also copied `/root/res/*` from the DUT by scp every
10 minutes, 54 files and 3.2 MB at the end, so about one window in eleven of
every run up to the middle of `b13p` of `x/` had one such login on the DUT
inside it. It was stopped then, and the runs after it are without it. One such
copy was timed on the idle DUT after the last run, with the `cpu` line of the
DUT's `/proc/stat` read every second around it: 87 files and 4.0 MB in 1.15 s,
and the DUT busy for 0.12 and 0.15 CPU seconds in the two seconds the copy
spans against 0.02 to 0.05 in the twelve around them. A copy therefore cost at
most 0.2 CPU seconds on the DUT, which is 0.007 cores averaged over a window
of 30 s and 0.004 over one of 45 s.

## Job 20529, the afternoon of 2026-11-13 (`pm6/`, `lpc/`, `cov/`)

OAR job 20529, 13:04 to 16:04, deployed on the image of `v2026.1109.0`, harness
of the working tree that became `490e676`.

`pm6/` is the first pass of `pm6`: the B3 base cells (1 pktgen thread, N of
100, 10, 1 and 1000) with turbo and C6 off for none, rfm, rfm sampled,
NetObserv, hsflowd, pmacctd and softflowd, five rounds, labels
`pm fixed t1 N<n> r<r> <monitor>`. 17 of its 140 windows have no traffic:
`gen_start` passed `--count 4000000000`, which pktgen exhausts after about 25
minutes at 2.65 Mpps. The harness passes `--count 0` since then, and the
weekend repeats the phase. The paper uses the weekend's.

`lpc/` is the first check of the libpcap counts of `measure.nu --counts` on a
NIC: b1 with two rounds of pmacctd and softflowd (16 windows). `cov/` is the
first pass of `b4cov` (15 windows), the share of the offered flows each
monitor reports over a 30 s window. The weekend repeats both.

## Two more NICs (`gros/`, `dahu/`)

The accuracy cells `setup b1 b2` with rfm, NetObserv and hsflowd on two more
pairs booted from the same image, three rounds of the offload cases and two
of the sweep, 96 windows each and none failed:

- `gros/`: job 7023876 at Nancy, gros-8 (DUT) and gros-9, one 18-core Xeon
  Gold 5220, ConnectX-4 Lx at 25 GbE (mlx5).
- `dahu/`: job 3169855 at Grenoble, dahu-20 (DUT) and dahu-24, two 16-core
  Xeon Gold 6130, Intel X710 at 10 GbE (i40e). The port count is the sum of
  `port.rx_unicast`, `port.rx_multicast` and `port.rx_broadcast` (and the tx
  ones).

`xhw.py` tabulates the packets each monitor reports against the port
(`xhw.txt`) and `xhw_bytes.py` the bytes against the port's bytes less 4
bytes of frame check sequence per frame (`xhw_bytes.txt`). With GRO on
NetObserv and hsflowd report 4.25 and 4.26% of the received packets on gros
and 10.45 and 11.20% on dahu, with TSO on 2.2% of the sent ones on both, and
99.9 to 100.0% with GRO off. rfm's exact counters read 99.99 to 100.02% in
every cell of both clusters and its estimate 98.2 to 100.7% as cell means.

## The weekend campaign (`weekend/`)

`weekend/run.sh` ran

```
SRC=~/rfm-bench-w R3="1 2 3 4 5" R2="1 2 3 4 5" RB4="1 2 3 4 5" \
ACC="rfm_acc netobserv hsflowd pmacctd softflowd" \
campaign.sh 20530 ~/rfm-weekend setup b1 b12 b2 b4 b11 b3 b7 b5 b8 b9 pm sparse pm6 b4cov
```

from 2026-11-13 19:04 to 2026-11-14 17:39: five rounds of every cell, three
of the program variants timed in place (b8, b9), 1442 `measure.nu` calls and
none failed. `rfm-kavlan-20530.log` is the deploy.

One window is invalid, b1 `tx_tso r3 softflowd`: a third driver started by
mistake at 20:21:27 on 2026-11-13, replaced `/root/workload` and
`/root/progbench` on both nodes and killed iperf3 before it was stopped ten
seconds later. The send stream was restarted by hand and the directories
restored from `~/rfm-bench-w` at 20:21:58. That window read 43.1 Gbit/s where
the other cells read 98.8. `check.py` and `figdata.py` leave it out, and the
cell keeps four rounds.

What the paper takes from it: the accuracy tables and the merge sweep (b1,
b2, b12, with pmacctd and softflowd), per packet cost and whole host cost
(b3, b7, pm, pm6, sparse), memory and flow coverage (b4, b4cov), the replay
of the program variants (b5), TCX against XDP on the flood (b8, b9), and
rate changes, restarts and the first set of ramps (b11).

Two limits of this run that later runs address:

- `control.nu --timeline` divided each delta of the ramp by a nominal second
  where the loop took 1.09 to 1.18 s. `figdata.py` scales those rows, and
  `ctl/` repeats the ramp with a timestamp on every read.
- `progbench insitu` measured b8 and b9 with the kernel's run time statistics
  on, which adds two clock reads to every program run. `ctl/` and `y/` repeat
  the bulk windows with the statistics off.

## Cohorts and power settings one at a time (`weekend2/`)

`setup b13 pm3` from `~/rfm-bench-w2` (the harness of `490e676`), 220 calls
and none failed. New files: `b13.jsonl` (60 windows) and `pm3.jsonl` (160),
and 320 `cstate pm3` lines in `campaign.log`.

`b13` adds a pktgen UDP flood of 20000 flows to the 8 bulk TCP connections,
capped at 100, 300, 1000 and 3000 Mbit/s, with the port count as the total
and the kernel's UDP counters as the count of the flood. The two highest
settings reached the same 1.02 Mpps, so there are three mixes: UDP is 2.5,
7.2 and 11.2% of the received packets. NetObserv and hsflowd report 2.7% of
the TCP packets at every mix. hsflowd reports 99.6 to 99.7% of the flood,
and a flood that is 11.2% of the packets is 82% of what it reports. NetObserv
reports 93.8 and 67.2% of the flood at the two higher rates, because its
kernel map of 5000 flows drops the samples of flows that do not fit.

`pm3` runs the cells at 2.65 Mpps and N of 100 and 10 with turbo and C6
switched one at a time (`dflt`, `noturbo`, `noc6`, `fixed`), and the log
carries the idle time of every state before and after each call. rfm with a
stage of 32 reads 0.29 to 0.36 busy cores below the empty server whenever C6
is enabled and 0.17 to 0.27 above it whenever C6 is disabled, with turbo on
or off. With C6 on and nothing attached 86 to 87 of the 96 CPUs rest in C6,
with rfm 76 to 78.

## Replay with later objects (`weekend3/`)

`setup b5` from `~/rfm-bench-w3`, whose 21 objects are built from rfm
`af79f9d` (the first gap of a slot drawn from the stationary distribution)
and `ed49eed` (`skb_unit_array` and `sampled_skip_skb`, the exact and the
sampling-only program counting one packet per skb). New files:
`b5-progbench.jsonl` (720 rows, 7 trials of 2 million runs a cell) and the
two `b5-accuracy-*.jsonl`. The wire unit costs 1.2 ns on a single TCP segment
(13.2 against 12.0 ns a run), 1.4 on a TSO skb at egress and 8.2 on a merged
skb at ingress, where the variant source parses the headers. The stationary
first gap costs 0.1 ns at N=100.

## Control run (`ctl-dry/`, `ctl/`)

`ctl/run/run.sh`, harness `~/rfm-bench-ctl` (workload of `4eacd75`, the
weekend's objects), `setup b9s b13s ramp` with five rounds. Its dry pass
found a fault in the check of the `acct` helper, and the wrapper left b1c out
as designed. New files: `b9s.jsonl` (47 rows), `b13s.jsonl` (15) and
`ramp.jsonl` (10 timelines).

- `b9s`: the bulk TCP windows of the exact program at TCX
  (`skip_array_lazy_nowake`) and at XDP (`xdp_skip_array`) with the run time
  statistics on and off and with nothing attached, GRO on and off, default
  power settings. With GRO on and the statistics off the host is busy on 5.89
  cores with nothing attached, 6.01 with the TCX program and 7.42 with the
  XDP one. Three rows with GRO off are missing: those runs took about 77 s
  each and the phase hit its timeout of 2400 s.
- `b13s`: the highest mix of b13 with NetObserv's table at 65536 entries
  beside its default and hsflowd. The flood reached 1.22 Mpps. NetObserv
  reported 60.1% of it at the default table and 100.0% with the enlarged one,
  hsflowd 99.8%, and both still 2.7% of the TCP packets.
- `ramp`: the ramp of b11 again, five runs with the rate fixed at N=1 and
  five with adaptive sampling, every row with its own interval `dt`. The last
  step read 17.20 to 17.63 Mpps. With the rate fixed the reader fell behind
  for the whole step in one run of five (four of five in the weekend's set).

## Stage, accounting programs and further mixes (`x-dry/`, `x/`)

`x/run/run.sh`, harness `~/rfm-bench-x` (workload of `c31b7ff`, the weekend's
objects), `setup pm3s b1c b13p` with five rounds, after a dry pass without a
failing call. New files: `pm3s.jsonl` (40 windows), `pm3s-cpu.jsonl` (80
snapshots of every CPU), `b1c.jsonl` (100) and `b13p.jsonl` (80). 220 calls
and none failed, from 23:45:27 to 05:03:46.

- `pm3s`: the cells at 2.65 Mpps and N=100 at the default power settings and
  with C6 off, for the tuned rfm with its stage of 32 events (`rfm`), the
  same configuration with `stage_events` at 1 and so without the stage's
  flush timer (`rfm_nostage`), NetObserv and nothing. The `cstate pm3s` lines
  of the log add the counts of timer softirqs and interrupts to the idle
  times, and `percpu.nu` snapshots every CPU around each call. With C6 on,
  rfm with the stage reads 0.30 busy cores below the empty server, 11.7 CPUs
  rest in C1E where 2.5 do on the empty server, and the hrtimer softirq runs
  5107 times a second, 5053 of them on the 63 CPUs that receive. Without the
  stage the idle states split as on the empty server and rfm reads 0.25
  cores above it, NetObserv 0.24. With C6 off the stage moves the busy cores
  by 0.01. Time per packet: 65.5 ns with the stage and 77.5 without at the
  default settings, 34.4 and 36.3 with C6 off.
- `b1c`: bulk TCP received over 8, 16, 32 and 64 connections with GRO on and
  off, with the `sd_fw` programs of systemd's IP accounting on the path of
  the receiving sockets (`acct_on`, the image's default) and detached
  (`acct_off`), with no monitor and at 8 connections with rfm as well, 45 s
  windows, 100 in all. With GRO on every cell fills the link at 98.8 Gbit/s,
  on 5.25, 6.54, 9.26 and 11.39 busy cores with the programs detached and 2
  to 3% more with them. With GRO off and the programs detached every cell
  still fills the link, on 10.85, 14.48, 18.18 and 18.94 cores, 1.7 to 2.2
  times the cores per bit. With the programs attached GRO off carries 86.6
  and 94.3 Gbit/s at 8 and 16 connections on 14.06 and 20.78 cores and fills
  the link at 32 and 64 on 36.11 and 38.68, 3.0 to 3.8 times the cores per
  bit. The weekend's accuracy cell (8 connections, programs attached) read
  75.2 Gbit/s with GRO off. One run of an accounting program takes 138 ns
  with GRO off at 8 connections, by the statistics window of the rfm cells
  (114.8 ns a run over five programs a packet, 23.9 for rfm alone with the
  others detached).
- `b13p`: the cohort of `b13` past the share one flood thread reaches, with
  2, 4 and 8 pktgen threads at full rate beside the 8 bulk TCP connections
  (`t2`, `t4`, `t8`) and with 8 threads beside connections paced to 2.5
  Gbit/s each (`t8p`), for rfm, NetObserv at its default table and at 65536
  entries, and hsflowd, 80 windows of 45 s. The flood reached 2.21, 4.35,
  9.10 and 17.03 Mpps, which is 21.6, 35.5, 54.3 and 90.8% of the received
  packets. Reported UDP share: rfm 21.5, 35.1, 55.6 and 90.8% as cell means
  and within 0.12 points of the true share of its own window in every
  window, hsflowd 90.9, 95.3, 97.8 and 99.8%, NetObserv 81.8, 87.7, 92.8 and
  99.3% at the default table and 91.1, 95.2, 97.8 and 99.8% with the
  enlarged one. NetObserv's default table kept 44.3, 34.6, 29.9 and 27.5% of
  the flood, the table model gives 44.4, 34.7, 29.9 and 27.5. hsflowd
  reported 99.8 and 99.7% of the flood at the first two rates, 91.3% at 9.1
  Mpps (80.1 to 96.7 over the rounds) and 67.6% at 17.0, and 2.71, 2.71,
  2.43 and 1.53% of the TCP packets.

## XDP with the power settings fixed (`y-dry/`, `y/`)

`y/run/run.sh`, harness `~/rfm-bench-y` (workload of `1968050`, the weekend's
objects), `setup b8s b9s b9p env` with five rounds and `PWR=fixed`, which
turns turbo off and disables C6 on the DUT for the three measuring phases,
after a dry pass of those phases without a failing call. New files:
`b8s-fixed-t1.jsonl`, `b8s-fixed-t4.jsonl` and `b8s-fixed-t8.jsonl` (45 rows
each), `b9s-fixed.jsonl` (70), `b9p-fixed-<label>.txt`, `.net` and `.json` for
four labels, and `env-<address>.txt` for both nodes. From 05:15:02 to
06:48:57, every call at exit 0. The labels are those of `ctl/`: `none`
attaches nothing, `empty` and `xdp_empty` are programs that do nothing at TCX
and at XDP, `skip_array_lazy_nowake` is the exact program at TCX and
`xdp_skip_array` at XDP.

- `b8s`: the flood windows of the XDP comparison (60 byte frames over 1000
  flows, 1, 4 and 8 pktgen threads, N=100 and N=1000 at 8 threads) with the
  run time statistics off and on, five rounds of 20 s. With the statistics off
  the exact program adds 0.18 busy cores at TCX and 0.20 at XDP at 2.67 Mpps,
  0.69 and 0.58 at 8.82 Mpps (XDP lower in each of five rounds, by 0.11), and
  1.25 and 1.27 at 17.31 Mpps, where the rounds spread by 0.27 and 0.34. The
  programs that do nothing add 0.11 and 0.13, 0.43 and 0.34, and 1.11 and
  0.87. With the statistics on the exact programs read 0.28 and 0.28, 1.16 and
  0.95, and 2.01 and 1.85. The weekend's flood windows (`b8`, `b9`, three
  rounds, default power settings, statistics on) had XDP 0.3 cores below TCX
  at 16.9 Mpps, which these rounds do not show.
- `b9s`: the bulk TCP windows over 8 connections, GRO on with all five labels
  and GRO off with `none` and the two exact programs, statistics on and off,
  five rounds of 20 s. GRO on, statistics off: 6.55 busy cores with nothing
  attached, 6.47 with `empty`, 6.59 with the exact program at TCX, 8.09 with
  `xdp_empty` and 8.08 with the exact program at XDP (sd 0.12 to 0.15). XDP
  less TCX by round is 1.50 (1.32 to 1.67), `xdp_empty` less `none` 1.53, and
  the two XDP programs differ by -0.01 (-0.22 to 0.29). With the statistics on
  the XDP programs read 8.01 and 8.46, at 24.3 and 45.5 ns a run. GRO off,
  statistics off: 12.61 cores at 52.3 Gbit/s with nothing attached, 12.43 at
  50.9 with TCX and 12.60 at 51.4 with XDP, which is 2.41, 2.44 and 2.45 cores
  per 10 Gbit/s. No run was lost to the timeout. The exact counts are within
  0.006% (TCX) and 0.014% (XDP) of the port in every window.
- `b9p`: a kernel profile of one bulk TCP window per label (`none`, the exact
  program at TCX, `xdp_empty`, the exact program at XDP), GRO on, statistics
  off, by `kprofile.nu`: bpftrace samples the instruction pointer of every CPU
  at 499 Hz for 20 s inside a progbench window of 45 s, 958080 samples each.
  `.txt` holds the samples per kernel address and per command in user mode,
  `.net` the programs on the port before and after, `.json` the line of
  progbench. Busy cores by the samples: 7.24, 7.31, 8.49 and 9.15, above the
  b9s cells because the profiler interrupts every CPU, idle ones included.
  With `xdp_empty` the copy to user space takes 0.68 cores more than with
  nothing attached (`_copy_to_iter`, `__check_object_size`) and the handling
  of pages and skbs 0.48 more (`napi_build_skb`). The exact program at XDP is
  charged 0.64 cores. `figdata.py` groups the functions (`data/kprofile.dat`,
  `data/kprofile-work.dat`).
- `env`: what the inventory of `setup` leaves out, for both nodes: the idle
  states with their latencies, the link, its FEC and receive hash, the private
  flags of the driver (`rx_striding_rq` on), the MTU (1500), the qdisc, TCP
  and BPF sysctls, the builds of the tools and every loaded program.

## The per packet cells of rfm's defaults with the power settings fixed (`z-dry/`, `z/`)

`z/run/run.sh`, harness `~/rfm-bench-z` (workload of `b25a755`, the weekend's
objects), `setup pm6d` with five rounds, after a dry pass. New file:
`pm6d.jsonl` (75 windows). The cells of `pm6` at N of 100, 10 and 1000 for
rfm with its defaults (`rfm_default`) and for the tuned configuration without
its stage (`rfm_nostage`), which `pm6` left out, beside the tuned rfm,
NetObserv and an empty window of the same round.

From 06:54:20 to 07:59:49 after a dry pass from 06:49:28 to 06:54:16, every
call at exit 0 and an empty `pm6d.err`. Program time per packet at N of 1000,
100 and 10, at 2.67 Mpps: the tuned rfm 40.8, 42.5 and 54.6 ns, rfm with its
defaults 40.9, 44.0 and 65.5, the tuned configuration without its stage 40.9,
44.2 and 73.3, NetObserv 42.4, 44.6 and 60.7. Busy cores over the empty window
of the same round (3.85): 0.18, 0.20 and 0.28 for the tuned rfm, 0.17, 0.18
and 0.29 with the defaults, 0.17, 0.19 and 0.33 without the stage, 0.21, 0.21
and 0.26 for NetObserv. By round the stage saves 0.1, 1.8 and 18.8 ns (11.0 to
23.5 at N of 10), where the two configurations without it spread over 62 to 72
and 66 to 79 ns. NetObserv's program is above the tuned rfm's in every round,
by 1.0 to 2.0, 1.4 to 2.7 and 5.4 to 7.3 ns. The cells that `pm6` also has
agree with it within 1.0 ns. The cost table of the paper takes its row for
rfm's defaults with the power settings fixed from this file and the other rows
from `pm6`.

## The MTU control of the XDP comparison (`m-dry/`, `m/`)

`m/run/run.sh`, harness `~/rfm-bench-m` (workload of `aee2465`, the weekend's
objects), `setup b9m` with five rounds and `PWR=fixed`, after a dry pass. New
files: `b9m-fixed-mtu1500.jsonl` and `b9m-fixed-mtu1700.jsonl` (10 rows each).
The bulk TCP windows of `b9s` (8 connections, GRO on, statistics off) with
nothing attached and with the XDP program that does nothing, at the DUT's own
MTU of 1500 and at 1700, the two in a shuffled order within each round. mlx5
sizes a receive buffer from the MTU and the headroom. At 1500 the 256 bytes of
headroom that XDP reserves take a buffer past half a page, so every frame gets
a page of its own where two shared one. An MTU of 1700 on the DUT alone gives
that layout with nothing attached, while the frames on the wire stay those of
the generator's MTU of 1500. iperf3 is restarted after each change of the MTU,
since the driver reopens its channels. The MTU is put back at the end and read
back.

From 08:02:02 to 08:13:51 after a dry pass from 08:00:14 to 08:01:59, every
call at exit 0, and the MTU read back as 1500 at the end. Busy cores over five
rounds of 20 s, all cells at 8.13 Mpps and 98.7 Gbit/s with 1518 bytes a frame
on the wire: 6.18 (sd 0.34) at 1500 with nothing attached and 7.90 (0.64) with
the XDP program that does nothing, 7.94 (0.69) at 1700 with nothing attached
and 7.84 (0.49) with the program. By round over the cell with nothing attached
at 1500: 1.71 (1.26 to 2.19), 1.75 (0.37 to 2.55) and 1.66 (1.28 to 2.33). The
15 windows with a page per frame span 7.14 to 8.97 cores and the 5 with two
frames per page 5.92 to 6.77. At 1700 the program changes the busy cores by
-0.10 (-1.27 to 1.17). The cells spread more than those of `b9s`, where one
set of iperf3 connections served all rounds. `figdata.py` writes
`data/xdp-mtu.dat`.
