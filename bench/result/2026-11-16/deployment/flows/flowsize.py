#!/usr/bin/env python3
# ruff: noqa: BLE001, PLW1510
# Read-only flow record sizes from the live flow tables. `rfm flows` reads the agent's table over
# its control socket and does not scrape its metrics.
#
# A flow stays in the table for the eviction timeout (30 s on the fleet) after its last packet,
# so a snapshot every 20 s sees every flow after its last packet. The counts of a flow entry are
# cumulative since the flow was created, and `packets` is the number of sampled wire packets:
# a sampled skb of g packets adds g. The agent does not keep the number of sampled skbs.
#
# A record is one entry of the table: interface, direction, protocol, addresses and ports, and
# the time of its first packet. The agent dates that time from a boot epoch which it reads anew
# on every request, so `first_seen` of one entry differs by nanoseconds between 2 snapshots and
# cannot be part of the key. The key is the rest, and an entry counts as a new record when its
# first_seen is more than 5 s away from that of the record under the same key. An entry is
# created again no sooner than 30 s after the one before it. The script of 2026-11-09 had
# first_seen in the key and counted every entry once per snapshot.
#
# Flow keys carry addresses. They are hashed in memory and never written. Per record the output
# holds, in this order:
#   p1, e1   sampled packets and estimated packets at the last snapshot that saw the record
#   proto, direction
#   i0, i1   index of the first and of the last snapshot that saw the record
#   p0, e0   sampled and estimated packets at the first snapshot that saw the record
#   grow     number of later snapshots in which the sampled packets had grown, each of which
#            holds at least 1 sampled skb
# A record with i0 = 0 existed before the window, and p1 - p0 and e1 - e0 are what it gained in
# the window. A record with i1 below the last index had left the table before the run ended.
#
#   python3 -I flowsize.py --out DIR --secs 7200 --every 20 node ...
import argparse
import hashlib
import itertools
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# directory of the ssh control sockets
CM = os.environ.get("FLEET_CM", "/tmp")
KEY = ("interface", "direction", "proto", "src", "dst", "src_port", "dst_port")
COLS = ("p1", "e1", "proto", "direction", "i0", "i1", "p0", "e0", "grow")
STAMP = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)$")


def epoch(s):
    m = STAMP.match(s)
    base = datetime.fromisoformat(m.group(1) + ("+00:00" if m.group(3) == "Z" else m.group(3)))
    return base.timestamp() + float(m.group(2) or 0)


def snap(node):
    cmd = ["ssh", "-C", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
           "-o", "ControlMaster=auto", "-o", f"ControlPath={CM}/cm-%C",
           "-o", "ControlPersist=15m", node,
           "sudo -n rfm flows top 10000000 --by packets --json"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    return json.loads(r.stdout) if r.stdout.strip().startswith("[") else None


def run(node, out, secs, every):
    live = {}   # key hash -> [first_seen, record]
    ended = []  # records replaced by a later entry under the same key
    times = []
    failed = shrunk = twice = 0
    idx = -1
    t_start = time.time()
    t_end = t_start + secs
    checked = False
    while True:
        t0 = time.time()
        try:
            fs = snap(node)
        except Exception as e:
            print(f"{node}: {e}", file=sys.stderr)
            fs = None
        t1 = time.time()
        if fs is None:
            failed += 1
        else:
            idx += 1
            times.append([round(t0, 2), round(t1, 2), len(fs)])
            if fs and not checked:
                # names of the fields only, never their values
                missing = [x for x in (*KEY, "first_seen", "packets", "est_packets") if x not in fs[0]]
                print(f"{node}: first snapshot {len(fs)} flows, missing fields {missing}", file=sys.stderr)
                checked = True
            for f in fs:
                k = "|".join(str(f.get(x, "")) for x in KEY)
                h = hashlib.blake2b(k.encode(), digest_size=12).digest()
                born = epoch(f["first_seen"])
                p, e = f.get("packets", 0), f.get("est_packets", 0)
                old = live.get(h)
                if old is not None and abs(born - old[0]) <= 5.0:
                    rec = old[1]
                    if rec[5] == idx:
                        twice += 1
                    if p > rec[0]:
                        rec[0], rec[1] = p, e
                        rec[8] += 1
                    elif p < rec[0]:
                        shrunk += 1
                    rec[5] = idx
                    continue
                if old is not None:
                    ended.append(old[1])
                live[h] = [born, [p, e, f.get("proto", 0), f.get("direction", ""), idx, idx, p, e, 0]]
        if time.time() >= t_end:
            break
        time.sleep(max(0.0, every - (time.time() - t0)))
    gap = max((b[0] - a[0] for a, b in itertools.pairwise(times)), default=0.0)
    flows = ended + [v[1] for v in live.values()]
    with open(out / f"{node}.flowsize.json", "w") as fh:
        json.dump({"node": node, "snapshots": idx + 1, "failed": failed, "shrunk": shrunk, "twice": twice,
                   "secs": secs, "every": every, "t0": t_start, "t1": time.time(), "max_gap": round(gap, 2),
                   "times": times, "cols": COLS, "flows": flows}, fh)
    print(f"{node}: done, {idx + 1} snapshots, {failed} failed, longest gap {gap:.1f} s, {len(flows)} records, "
          f"{shrunk} counts that shrank, {twice} keys seen twice in a snapshot", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--secs", type=int, default=7200)
    ap.add_argument("--every", type=int, default=20)
    ap.add_argument("nodes", nargs="+")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    ts = [threading.Thread(target=run, args=(n, out, a.secs, a.every)) for n in a.nodes]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


if __name__ == "__main__":
    main()
