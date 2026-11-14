#!/usr/bin/env python3
"""
Standard error of rfm's gap sampler on a flow whose skbs arrive with a fixed
period, as a ratio to that of independent 1 in N sampling, for every period up
to 8 N. The ratio is exact, from the renewal equation of the gaps, and a direct
simulation of the sampler checks it.

The sampler draws the skip to the next sample uniformly from 0 to 2N - 2, so
the gap between samples is uniform on 1 to 2N - 1 with mean N, and it starts
in the stationary state (rfm_gap and rfm_gap_first in bpf/rfm_tc.c). For a
stationary renewal process the count X of samples on the M positions
0, p, 2p, ... has

    Var X = M c(0) + 2 sum_{d=1}^{M-1} (M - d) c(d p)
    c(k) = (u(k) - 1/N) / N

where u(k) is the chance of a sample k positions after a sample. Independent
sampling has the binomial variance M c(0), so the ratio of the standard errors
is sqrt(1 + 2 sum (1 - d/M) c(d p) / c(0)).
"""

import argparse
import math
import random


def renewal(n, kmax):
    # u(k) for k = 0..kmax with gaps uniform on 1..2n-1, by a sliding sum
    w = 2 * n - 1
    u = [1.0] + [0.0] * kmax
    pref = [0.0, 1.0]
    for k in range(1, kmax + 1):
        u[k] = (pref[k] - pref[max(0, k - w)]) / w
        pref.append(pref[k] + u[k])
    return u


def ratio(n, p, m, u):
    c0 = (1 - 1 / n) / n
    s = 0.0
    for d in range(1, m):
        k = d * p
        # u has settled to 1/n long before the table ends
        if k >= len(u):
            break
        s += (1 - d / m) * (u[k] - 1 / n) / n
    return math.sqrt(max(0.0, 1 + 2 * s / c0))


def simulate(n, p, m, trials, rng):
    # the sampler itself from a stationary start, the first skip is the smaller of two distinct draws
    w = 2 * n - 1
    xs = []
    for _ in range(trials):
        a = rng.randrange(w + 1)
        b = a + 1 + rng.randrange(w)
        if b > w:
            b -= w + 1
        pos = min(a, b)
        x = 0
        while pos < p * m:
            if pos % p == 0:
                x += 1
            pos += 1 + rng.randrange(w)
        xs.append(x)
    mean = sum(xs) / len(xs)
    return mean, math.sqrt(sum((x - mean) ** 2 for x in xs) / (len(xs) - 1))


ap = argparse.ArgumentParser()
ap.add_argument("--rates", default="10,100,1000")
ap.add_argument("--samples", type=int, default=100, help="samples expected of the flow, its skbs over N")
ap.add_argument("--trials", type=int, default=20000, help="simulated flows per check, 0 skips the checks")
ap.add_argument("--seed", type=int, default=1)
args = ap.parse_args()

rng = random.Random(args.seed)
for n in (int(x) for x in args.rates.split(",")):
    u = renewal(n, 400 * n)
    m = args.samples * n
    rs = [(ratio(n, p, m, u), p) for p in range(1, 8 * n + 1)]
    worst, best = max(rs), min(rs)
    print(f"N={n} flow of {m} skbs: back to back {ratio(n, 1, m, u):.4f}, period N {ratio(n, n, m, u):.4f}, "
          f"worst {worst[0]:.4f} at period {worst[1]}, best {best[0]:.4f} at period {best[1]}, "
          f"{sum(1 for r, _ in rs if r > 1.01)} of {len(rs)} periods over 1.01")
    if args.trials and n <= 100:
        for p in (1, n, 2 * n - 1):
            mean, sd = simulate(n, p, m, args.trials, rng)
            print(f"  simulated period {p}: mean {mean:.2f} of {m / n:.0f}, ratio {sd / math.sqrt(m * (1 - 1 / n) / n):.4f} "
                  f"against {ratio(n, p, m, u):.4f}")
