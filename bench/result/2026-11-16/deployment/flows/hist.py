#!/usr/bin/env python3
# The histogram of flow record sizes from flowsize.py's per record files, which hold no keys.
# The per record files stay out of the archive, this histogram is what the numbers come from.
#
# Units. The agent counts sampled wire packets per record: a sampled skb of g packets adds g.
# It does not keep the number of sampled skbs s, and the standard error of an estimate is about
# 1/sqrt(s). Without merged skbs s equals the sampled packets. With g packets per skb a record
# needs 100 * g sampled packets for 100 sampled skbs. A record also holds at least 1 sampled skb
# per snapshot in which it had grown.
#
# Per record, in the window between the first and the last snapshot:
#   pw  sampled packets gained   (p1 - p0 when the record existed at the first snapshot, else p1)
#   ew  estimated packets gained (e1 - e0, else e1)
#   sk  snapshots in which it grew, plus 1 when it was created in the window
# Three views per host, each as buckets [size, records, estimated packets], with the size exact
# up to 100 and then the power of two that bounds it from above:
#   buckets         records by pw, weighted with ew: what an estimate over the window rests on
#   buckets_life    records by p1, their sampled packets since creation, weighted with ew
#   buckets_inside  records created and ended inside the window by p1, weighted with e1
# "ge" holds [records, estimated packets] per view for the thresholds 10, 100 and 4500 sampled
# packets (100 skbs at 45 packets of 1448 bytes in an skb of 64 KB), and "sure" for the records
# that hold 100 sampled skbs for certain: pw >= 4500 or sk >= 100.
#   python3 -I hist.py DIR OUT_JSON
import json
import sys
from collections import defaultdict
from pathlib import Path

d, out = Path(sys.argv[1]), Path(sys.argv[2])
MERGED = 45
CUTS = (10, 100, 100 * MERGED)
VIEWS = ("window", "life", "inside")


def bucket(s):
    if s <= 100:
        return s
    b = 128
    while b < s:
        b *= 2
    return b


def share(part, whole):
    return part / whole if whole else 0.0


res = {}
tot = defaultdict(float)
for f in sorted(d.glob("*.flowsize.json")):
    v = json.loads(f.read_text())
    last = v["snapshots"] - 1
    bk = {name: defaultdict(lambda: [0, 0]) for name in VIEWS}
    ge = {name: {str(c): [0, 0] for c in (*CUTS, "sure")} for name in VIEWS}
    by_dir = defaultdict(int)
    n = n_pre = n_idle = n_inside = 0
    for p1, e1, _proto, dirn, i0, i1, p0, e0, grow in v["flows"]:
        n += 1
        pre = i0 == 0
        n_pre += pre
        pw, ew = (p1 - p0, e1 - e0) if pre else (p1, e1)
        sk = grow if pre else grow + 1
        inside = not pre and i1 < last
        n_inside += inside
        if pw <= 0:
            n_idle += 1
        else:
            by_dir[dirn] += ew
        for name, size, weight, take in (("window", pw, ew, pw > 0), ("life", p1, ew, pw > 0), ("inside", p1, e1, inside)):
            if not take:
                continue
            b = bk[name][bucket(size)]
            b[0] += 1
            b[1] += weight
            hits = [str(c) for c in CUTS if size >= c]
            if size >= 100 * MERGED or (name == "window" and sk >= 100):
                hits.append("sure")
            for k in hits:
                ge[name][k][0] += 1
                ge[name][k][1] += weight
    est = {name: sum(b[1] for b in bk[name].values()) for name in VIEWS}
    recs = {name: sum(b[0] for b in bk[name].values()) for name in VIEWS}
    res[v["node"]] = {
        "snapshots": v["snapshots"], "failed": v.get("failed", 0), "shrunk": v.get("shrunk", 0), "twice": v.get("twice", 0),
        "secs": v["secs"], "every": v["every"], "t0": v.get("t0"), "t1": v.get("t1"), "max_gap": v.get("max_gap"),
        "records": n, "from_before": n_pre, "idle_in_window": n_idle, "inside": n_inside,
        "est": est, "est_window_by_direction": dict(by_dir), "ge": ge,
        "buckets": [[k, b[0], b[1]] for k, b in sorted(bk["window"].items())],
        "buckets_life": [[k, b[0], b[1]] for k, b in sorted(bk["life"].items())],
        "buckets_inside": [[k, b[0], b[1]] for k, b in sorted(bk["inside"].items())],
    }
    for name in VIEWS:
        tot[f"e_{name}"] += est[name]
        tot[f"r_{name}"] += recs[name]
        for k, g in ge[name].items():
            tot[f"r_{name}_{k}"] += g[0]
            tot[f"e_{name}_{k}"] += g[1]
    g = ge["window"]
    print(f"{v['node']}: {v['snapshots']} snapshots, {v.get('failed', 0)} failed, longest gap {v.get('max_gap')} s, "
          f"{n} records ({n_pre} from before, {n_idle} of them idle, {n_inside} created and ended inside), "
          f"{est['window']} estimated packets in the window, share in records of 10+ sampled packets {share(g['10'][1], est['window']):.4f}, "
          f"100+ {share(g['100'][1], est['window']):.4f}, 4500+ {share(g['4500'][1], est['window']):.4f}, "
          f"100+ skbs for sure {share(g['sure'][1], est['window']):.4f} | by size since creation 100+ "
          f"{share(ge['life']['100'][1], est['life']):.4f} | inside records 100+ {share(ge['inside']['100'][1], est['inside']):.4f}")
out.write_text(json.dumps(res))
if tot["e_window"]:
    print(f"all {len(res)} hosts: {int(tot['r_window'])} records that grew in the window, "
          f"{share(tot['r_window_100'], tot['r_window']):.4f} of them with 100+ sampled packets, "
          f"{int(tot['e_window'])} estimated packets")
    for name in VIEWS:
        for k in ("10", "100", "4500", "sure"):
            per = sorted(share(r["ge"][name][k][1], r["est"][name]) for r in res.values())
            print(f"  {name} {k}: pooled {share(tot[f'e_{name}_{k}'], tot[f'e_{name}']):.4f}, per host {per[0]:.4f} to {per[-1]:.4f}, "
                  f"median {per[len(per) // 2]:.4f}, hosts at 0.9 or more {sum(1 for x in per if x >= 0.9)}, "
                  f"at 0.5 or more {sum(1 for x in per if x >= 0.5)}")
