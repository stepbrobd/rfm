#!/usr/bin/env python3
# ruff: noqa: BLE001, PLW1510
# Read-only flow size distribution from the live flow tables. A flow stays in the table for the
# eviction timeout (30 s on the fleet) after its last packet, so a snapshot every 20 s sees every
# flow after its last packet and its largest count is its final one. Flow keys carry addresses,
# they are hashed in memory and never written: the output holds per flow sampled packets,
# estimated packets, protocol and direction only.
#
#   python3 -I flowsize.py --out DIR --secs 7200 --every 20 node ...
import argparse
import hashlib
import json
import subprocess
import sys
import threading
import time
from pathlib import Path


def snap(node):
    cmd = ["ssh", "-C", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
           "-o", "ControlMaster=auto", "-o", "ControlPath=/tmp/claude-1000/fleet-%r@%h",
           "-o", "ControlPersist=15m", node,
           "sudo -n rfm flows top 10000000 --by packets --json"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    return json.loads(r.stdout) if r.stdout.strip().startswith("[") else None


def run(node, out, secs, every):
    flows = {}
    snaps = 0
    t_end = time.time() + secs
    while True:
        t0 = time.time()
        try:
            fs = snap(node)
        except Exception as e:
            print(f"{node}: {e}", file=sys.stderr)
            fs = None
        if fs is not None:
            snaps += 1
            for f in fs:
                k = "|".join(str(f.get(x, "")) for x in ("interface", "direction", "proto", "src", "dst", "src_port", "dst_port", "first_seen"))
                h = hashlib.blake2b(k.encode(), digest_size=12).digest()
                p, e = f.get("packets", 0), f.get("est_packets", 0)
                old = flows.get(h)
                if old is None or p > old[0]:
                    flows[h] = (p, e, f.get("proto", 0), f.get("direction", ""))
        if time.time() >= t_end:
            break
        time.sleep(max(0.0, every - (time.time() - t0)))
    with open(out / f"{node}.flowsize.json", "w") as fh:
        json.dump({"node": node, "snapshots": snaps, "secs": secs, "every": every,
                   "flows": [list(v) for v in flows.values()]}, fh)


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
