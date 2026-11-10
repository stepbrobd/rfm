# RFM on v2026.1109.0: power settings, table size and accuracy checks, 2026-11-10 (Grid'5000 Louvain, spirou, routed KaVLAN)

Same testbed, roles, harness and rfm configurations as `../2026-11-09/`, on the
image of `v2026.1109.0` (rfm 2026.1109.0, kernel 7.3.1, nixpkgs `0dea955`),
whose agent creates event rings for the online CPUs only. spirou has as many
online as possible CPUs (96), so the agent's maps and code path match
2026.1105.0 there, and these runs check that against the night of
2026-11-09.

## Slack run (`slack/`)

The night job 20519 ended its phases at 03:05 with its walltime to 08:30. Its
nodes, spirou-7 (DUT) and spirou-8 (generator) in KaVLAN 4, were redeployed
on the new image at 03:10 and `slack/launch.sh` then ran:

```
SRC=~/rfm-d2-src campaign.sh 20519 ~/rfm-n2 setup pm b4 b1
```

from the harness of `v2026.1109.0` (`ee034e9`), from 03:15 to 06:23, without
a failed `measure.nu` call. `slack/kadeploy.log` is the redeploy,
`slack/inventory-*.txt` the inventory per node (rfm 2026.1109.0 on the DUT).

`pm` runs the B3 cells of rfm exact, rfm `sampled_only`, NetObserv and an
empty baseline at 1 pktgen thread (2.65 Mpps) for N of 100, 10 and 1 and at 4
threads (8.4 to 8.6 Mpps) for N of 100 and 10, each round once with the DUT at
the image's default (`dflt`: turbo on, every C-state enabled) and once with
`intel_pstate/no_turbo` 1 and C6 disabled on every CPU (`fixed`), in shuffled
order, three rounds. The generator keeps its settings. The labels are
`pm <setting> t<threads> N<n> r<round> <variant>`.

At 2.65 Mpps the default settings put rfm with a stage of 32 at 0.3 to 0.4
busy cores below the empty baseline at N of 100 and 10, as on the night of
2026-11-09. With turbo and C6 off it reads 0.21 (N=100), 0.28 (N=10) and 0.61
(N=1) busy cores above it, against 0.22, 0.25 and 0.49 for NetObserv, so the
negative overhead comes from the power settings. ns per program run ranks the
same in both settings at every load: rfm exact at or below NetObserv, rfm
`sampled_only` below both. At 2.65 Mpps the runs take 30 to 40% less time with
C6 off, at 8.4 Mpps the settings change them by under 5%.

`b4` and `b1` repeat the night's cells on the new tag. rfm's maps (3131 KB for
the exact configuration), RSS and active flows at 1M offered flows, and its
estimated and exact counts against the wire under GRO and TSO, match the
night's within the round to round spread.

## Job 20520 (`job20520/`)

OAR job 20520, spirou-7 (DUT) and spirou-8 (generator) in KaVLAN 4, 09:05 to
12:05, deployed on the same image, with `job20520/launch.sh`:

```
SRC=~/rfm-d2-src campaign.sh 20520 ~/rfm-d2 setup sparse pm
```

from the harness at `fc30367`, which adds `sparse` and gives rfm
`max_sample_rate=N` above 1000, a rate rfm refuses otherwise. It ran from
09:08 to 11:55 without a failed `measure.nu` call.

`sparse` runs the B3 cells of rfm exact, rfm `sampled_only`, NetObserv,
hsflowd and an empty baseline at N=10000 with 1 and 4 pktgen threads and at
N=100000 with 1, three rounds, labelled `base N10000`, `hi N10000` and
`base N100000` like the night's B3 cells, and the B1 GRO and TSO cells at
N=10000. Past N=1000 every monitor's cost per packet stays flat: at 2.65 Mpps
rfm exact 68.6 and 69.4 ns at N=10000 and 100000, rfm `sampled_only` 44.2 and
45.0, NetObserv 59.9 and 60.1, hsflowd 95.9 and 98.2. At N=10000 rfm's exact
counters read 1.0001 of the wire in both directions, and its estimates
scatter by 0.7 to 3% a window from the fewer samples.

`pm` repeats the slack run's pass. The two replicates agree within their
round to round spread in every cell.
