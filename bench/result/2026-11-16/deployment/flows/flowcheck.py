#!/usr/bin/env python3
# Checks the flow table snapshots of flowsize.py against the exact counters: the estimated
# packets that the flow records of a host gained between its first and its last snapshot,
# against the exact IP packets of the same interval, read from the store's raw samples by
# linear interpolation (fleet.py edges). The 2 agree within the sampling error when the
# snapshots saw every record.
#
#   python3 -I flowcheck.py plan FLOWSIZE_DIR            prints "host start end" for fleet.py edges
#   python3 -I flowcheck.py check FLOWSIZE_DIR EDGES_DIR prints the table
import itertools
import json
import math
import sys
from pathlib import Path

cmd, d = sys.argv[1], Path(sys.argv[2])


def at(ts, vs, t):
    # linear interpolation of a counter at t (ms), None outside the samples
    for i in range(1, len(ts)):
        if ts[i - 1] <= t <= ts[i]:
            a, b = float(vs[i - 1]), float(vs[i])
            return a + (b - a) * (t - ts[i - 1]) / (ts[i] - ts[i - 1])
    return None


if cmd == "plan":
    for f in sorted(d.glob("*.flowsize.json")):
        v = json.loads(f.read_text())
        print(v["node"], int(v["times"][0][0]), int(v["times"][-1][1]) + 1)
    sys.exit(0)

ed = Path(sys.argv[3])
print("| node | snapshots | longest gap s | records | est in / exact rx | est out / exact tx | sampled in | 1/sqrt | resets |")
print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
worst = 0.0
for f in sorted(d.glob("*.flowsize.json")):
    v = json.loads(f.read_text())
    n = v["node"]
    e = json.loads((ed / f"{n}.edges.json").read_text())
    t_a = 1000 * (v["times"][0][0] + v["times"][0][1]) / 2
    t_b = 1000 * (v["times"][-1][0] + v["times"][-1][1]) / 2
    exact = {"rx": 0.0, "tx": 0.0}
    resets = 0
    ok = True
    for s in e["series"]:
        vs = [float(x) for x in s["v"]]
        resets += sum(1 for a, b in itertools.pairwise(vs) if b < a)
        a, b = at(s["t"], vs, t_a), at(s["t"], vs, t_b)
        if a is None or b is None:
            ok = False
            continue
        exact["rx" if "_rx_" in s["name"] else "tx"] += b - a
    est = {"ingress": 0, "egress": 0}
    samp = {"ingress": 0, "egress": 0}
    recs = 0
    for p1, e1, _proto, dirn, i0, _i1, p0, e0, _grow in v["flows"]:
        recs += 1
        est[dirn] = est.get(dirn, 0) + (e1 - e0 if i0 == 0 else e1)
        samp[dirn] = samp.get(dirn, 0) + (p1 - p0 if i0 == 0 else p1)
    rin = est["ingress"] / exact["rx"] if exact["rx"] else float("nan")
    rout = est["egress"] / exact["tx"] if exact["tx"] else float("nan")
    inv = 1 / math.sqrt(samp["ingress"]) if samp["ingress"] else float("nan")
    worst = max(worst, abs(rin - 1), abs(rout - 1))
    print(f"| {n} | {v['snapshots']} | {v.get('max_gap')} | {recs} | {rin:.4f} | {rout:.4f} | {samp['ingress']} | {inv:.4f} | "
          f"{resets}{'' if ok else ' (edge outside the samples)'} |")
print(f"\n- largest difference between the records' estimate and the exact count: {100 * worst:.2f}%")
