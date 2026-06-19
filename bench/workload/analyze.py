#!/usr/bin/env python3
"""
Summarize per-flow sampling error from accuracy.sh output against the
theoretical bound StdErr(P_hat)/P <= sqrt(N/P) (Duffield et al., IMW 2002).
"""

import argparse
import csv
import math

ap = argparse.ArgumentParser()
ap.add_argument("--csv", default="/tmp/rfm-accuracy.csv")
ap.add_argument("--rate", type=int, required=True)
ap.add_argument("--flows", type=int, required=True)
args = ap.parse_args()

with open(args.csv) as f:
    rows = list(csv.DictReader(f))
if not rows:
    raise SystemExit("no flows in " + args.csv)

M = int(rows[0]["ground_truth"])
rel = sorted(abs(int(r["scaled"]) - M) / M for r in rows)
coverage = len(rows) / args.flows
bound = math.sqrt(args.rate / M)


def q(p):
    return rel[min(len(rel) - 1, int(p / 100 * len(rel)))]


print(f"N={args.rate} M={M} seen={len(rows)}/{args.flows} coverage={coverage:.3f}")
print(
    f"rel_err mean={sum(rel) / len(rel):.4f} p50={q(50):.4f} "
    f"p95={q(95):.4f} max={rel[-1]:.4f}"
)
print(f"duffield_bound sqrt(N/M)={bound:.4f}")
