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
