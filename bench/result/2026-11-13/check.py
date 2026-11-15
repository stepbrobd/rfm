#!/usr/bin/env python3
# validity checks over every measure.nu window of this directory: the calls that failed, the
# rounds of each cell, the traffic that was there, drops at the port and in rfm's rings, and the
# sampling rate each monitor applied
# usage: python3 -I check.py > check.txt
import hashlib
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
# windows known to be invalid, as (file relative to this directory, label)
INVALID = {("weekend/res/b1.jsonl", "tx_tso r3 softflowd")}
# the run directories in the order their runs started
RUNS = ["pm6", "lpc", "cov", "gros", "dahu", "weekend", "weekend2", "weekend3", "ctl-dry", "ctl", "x-dry", "x", "y-dry", "y",
        "z-dry", "z", "m-dry", "m"]
# a window is flagged when its port rate leaves the median of its cell and variant by more
SPREAD = 0.10


def wire(nic, d):
    if f"port.{d}_unicast" in nic:
        return sum(nic[f"port.{d}_{k}"] for k in ("unicast", "multicast", "broadcast"))
    return nic.get(f"{d}_packets_phy", 0)


def wire_bytes(nic, d):
    return nic.get(f"port.{d}_bytes", nic.get(f"{d}_bytes_phy", 0))


def port_drops(nic):
    return sum(nic.get(k, 0) for k in ("rx_out_of_buffer", "rx_discards_phy", "tx_discards_phy", "port.rx_dropped"))


def applied(r):
    # the sampling rates a monitor's own output shows, None where it shows none
    c = r.get("counts") or {}
    a = r["agent"]
    if a == "netobserv":
        return sorted({q for x in c.get("by_direction", []) for q in x.get("rates", [])}) or None
    if a == "hsflowd":
        return sorted({q for x in c.get("by_port", []) for q in x.get("rates", [])}) or None
    if a == "rfm":
        out = set()
        for d in ("ingress", "egress"):
            est, smp = c.get(f"rfm_flow_packets_total.{d}"), c.get(f"rfm_flow_sampled_packets_total.{d}")
            if est and smp:
                out.add(round(est / smp, 3))
        return sorted(out) or None
    return None


def logs():
    print("# campaign logs")
    for log in sorted(HERE.glob("**/campaign.log")):
        text = log.read_text(errors="replace")
        ok, bad = len(re.findall(r"^exit=0$", text, re.M)), re.findall(r"^exit=[1-9]\d*$", text, re.M)
        phases = re.findall(r"^(\S+ \S+) === phase (\S+)$", text, re.M)
        done = re.findall(r"^(\S+ \S+) campaign done$", text, re.M)
        notes = re.findall(r"^.*(?:refusing|reads back|acct \S+ leaves).*$", text, re.M)
        span = f"{phases[0][0]} to {done[-1]}" if phases and done else "no campaign done"
        print(f"{log.relative_to(HERE)}: {ok} calls exit 0, {len(bad)} nonzero, phases {' '.join(p for _, p in phases)}, {span}")
        for n in notes:
            print(f"  note: {n[:200]}")


def windows():
    print("\n# measure.nu windows")
    flagged = []
    seen = {}
    # the directories in the order their runs started, since fetch copies every result file of
    # the dut again into the directory of each later run on the same nodes, and a file belongs
    # under the run that made it
    def started(q):
        top = q.relative_to(HERE).parts[0]
        return (RUNS.index(top) if top in RUNS else len(RUNS), str(q))
    order = sorted(HERE.glob("**/*.jsonl"), key=started)
    for path in order:
        rel = str(path.relative_to(HERE))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in seen:
            print(f"{rel}: the same bytes as {seen[digest]}")
            continue
        seen[digest] = rel
        rows = []
        for ln in path.read_text().splitlines():
            try:
                r = json.loads(ln)
            except json.JSONDecodeError:
                flagged.append(f"{rel}: a line that is not json")
                continue
            if isinstance(r, dict) and "nic" in r and "label" in r and "sys_cores" in r:
                rows.append(r)
        if not rows:
            continue
        cells = defaultdict(list)
        for r in rows:
            m = re.match(r"^(.*?) r(\d+) (\S+)$", r["label"])
            cells[(m.group(1), m.group(3)) if m else (r["label"], "")].append(r)
        secs = [r["secs"] for r in rows]
        rounds = sorted({len(v) for v in cells.values()})
        print(f"{rel}: {len(rows)} windows in {len(cells)} cells, rounds per cell {rounds}, window {min(secs):.1f} to {max(secs):.1f} s")
        for (cell, var), rs in sorted(cells.items()):
            rate = [(wire_bytes(r["nic"], "rx") + wire_bytes(r["nic"], "tx")) * 8 / r["secs"] / 1e9 for r in rs]
            med = statistics.median(rate)
            for r, x in zip(rs, rate):
                why = []
                nic = r["nic"]
                pk = wire(nic, "rx") + wire(nic, "tx")
                if (rel, r["label"]) in INVALID:
                    why.append("listed as invalid")
                if pk / r["secs"] < 1000:
                    why.append(f"no traffic ({pk / r['secs']:.0f} pps)")
                if med > 0 and abs(x - med) > SPREAD * med:
                    why.append(f"port rate {x:.2f} Gbit/s against the cell's median {med:.2f}")
                d = port_drops(nic)
                if pk and d / pk > 0.001:
                    why.append(f"port drops {100 * d / pk:.2f}% of the packets")
                if r.get("ring_drops", 0) > 0:
                    why.append(f"ring drops {r['ring_drops']}")
                ap = applied(r)
                if ap is not None and any(abs(q - r["n"]) > 0.02 * r["n"] for q in ap):
                    why.append(f"applied rate {ap} for a configured {r['n']}")
                if r["agent"] in ("rfm", "netobserv", "hsflowd") and (r.get("prog") or {}).get("secs") and not r["prog"].get("runs"):
                    why.append("no program runs in the stat window")
                if why:
                    flagged.append(f"{rel}: {r['label']}: " + ", ".join(why))
    print(f"\n# flagged windows: {len(flagged)}")
    for f in flagged:
        print(f)


if __name__ == "__main__":
    logs()
    windows()
    sys.exit(0)
