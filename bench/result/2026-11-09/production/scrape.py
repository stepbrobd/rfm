#!/usr/bin/env python3
# ruff: noqa: BLE001, PLW1510, SIM115
# Read-only production scrape: chained direct deltas of every node's rfm /metrics at a fixed
# cadence, so rollup series that appear, restart or expire between VictoriaMetrics samples are
# all counted. A rollup tuple expires only after ten eviction timeouts of silence (300 s on the
# fleet), longer than the cadence, so no increment is lost between two scrapes.
#
#   python3 -I scrape.py --out DIR --secs 7200 --every 60 node ...
# writes DIR/<node>.jsonl, one line per interval, and DIR/<node>.first.prom, the first scrape.
import argparse
import json
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)')
LAB = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
FLOW = ("rfm_flow_packets_total", "rfm_flow_bytes_total",
        "rfm_flow_sampled_packets_total", "rfm_flow_sampled_bytes_total")
IFACE = ("rfm_interface_rx_packets_total", "rfm_interface_rx_bytes_total",
         "rfm_interface_tx_packets_total", "rfm_interface_tx_bytes_total")
SINGLE = ("rfm_collector_created_flows_total", "rfm_collector_dropped_events_total",
          "rfm_collector_folded_flows_total", "rfm_collector_forced_evictions_total",
          "process_cpu_seconds_total", "rfm_ipfix_records_total", "rfm_ipfix_dropped_records_total")
GAUGE = ("rfm_collector_active_flows", "process_resident_memory_bytes", "rfm_bpf_sample_rate",
         "go_memstats_heap_inuse_bytes", "process_start_time_seconds")


def scrape(node):
    cmd = ["ssh", "-C", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
           "-o", "ControlMaster=auto", "-o", "ControlPath=/tmp/claude-1000/fleet-%r@%h",
           "-o", "ControlPersist=15m", node,
           "curl -s --max-time 25 'http://[::1]:9669/metrics'"]
    t = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return t, r.stdout


def parse(text):
    flow, iface, single, gauge = {}, {}, defaultdict(float), {}
    for ln in text.splitlines():
        if not ln or ln[0] == "#":
            continue
        m = LINE.match(ln)
        if not m:
            continue
        name, labs, val = m.group(1), m.group(2) or "", m.group(3)
        try:
            v = float(val)
        except ValueError:
            continue
        if name in FLOW:
            flow[(name, labs)] = v
        elif name in IFACE:
            iface[(name, labs)] = v
        elif name in SINGLE:
            single[name] += v
        elif name in GAUGE:
            gauge[name] = v
        elif name == "rfm_errors_total":
            single["errors." + dict(LAB.findall(labs)).get("subsystem", "")] += v
    return flow, iface, single, gauge


def delta(prev, cur):
    # a series new since the last scrape counts from zero, one below its last value restarted
    out, new, restarted = {}, 0, 0
    for k, v in cur.items():
        p = prev.get(k)
        if p is None:
            out[k] = v
            new += 1
        elif v < p:
            out[k] = v
            restarted += 1
        else:
            out[k] = v - p
    vanished = sum(1 for k in prev if k not in cur)
    return out, new, restarted, vanished


def run(node, out, secs, every):
    f = open(out / f"{node}.jsonl", "a")
    prev = None
    t_end = time.time() + secs
    while True:
        t0 = time.time()
        try:
            t, text = scrape(node)
        except Exception as e:  # a failed scrape breaks the chain, the next one restarts it
            print(f"{node}: {e}", file=sys.stderr)
            prev = None
            text = ""
        if text and "rfm_interface_rx_packets_total" in text:
            cur = parse(text)
            if prev is None:
                (out / f"{node}.first.prom").write_text(text)
            else:
                pt, (pf, pi, ps, _) = prev
                fd, new, rst, van = delta(pf, cur[0])
                idd, _, irst, _ = delta(pi, cur[1])
                agg = defaultdict(float)
                for (name, labs), v in fd.items():
                    d = dict(LAB.findall(labs))
                    agg[f"{name}|{d.get('direction', '')}|{d.get('proto', '')}"] += v
                ia = defaultdict(float)
                for (name, labs), v in idd.items():
                    d = dict(LAB.findall(labs))
                    ia[f"{name}|{d.get('family', '')}|{d.get('ifname', '')}"] += v
                rec = {
                    "node": node, "t0": pt, "t1": t, "dt": t - pt,
                    "flow": agg, "iface": ia,
                    "single": {k: cur[2][k] - ps.get(k, 0) for k in cur[2]},
                    "gauge": cur[3], "series": len(cur[0]) // 4,
                    "new": new, "restarted": rst, "vanished": van, "iface_restarted": irst,
                }
                f.write(json.dumps(rec) + "\n")
                f.flush()
            prev = (t, cur)
        else:
            prev = None
        if time.time() >= t_end:
            break
        time.sleep(max(0.0, every - (time.time() - t0)))
    f.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--secs", type=int, default=7200)
    ap.add_argument("--every", type=int, default=60)
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
