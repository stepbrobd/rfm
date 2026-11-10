#!/usr/bin/env python3
# ruff: noqa: B023
# Tables from measure.nu json lines. Labels are "<cell> r<round> <variant>", the cell's none rows
# of the same round are the baseline that busy cores subtract.
#   python3 -I measure_tables.py FILE.jsonl ...
import json
import math
import re
import sys
from collections import defaultdict


def ms(xs):
    xs = [x for x in xs if x is not None and not (isinstance(x, float) and math.isnan(x))]
    if not xs:
        return float("nan"), float("nan"), 0
    m = sum(xs) / len(xs)
    sd = math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1)) if len(xs) > 1 else 0.0
    return m, sd, len(xs)


def split(label):
    m = re.match(r"^(.*?) r(\d+) (\S+)$", label)
    if m:
        return m.group(1), int(m.group(2)), m.group(3)
    parts = label.rsplit(" ", 1)
    return (parts[0], 0, parts[1]) if len(parts) == 2 else (label, 0, "")


def wire(r, d):
    nic = r.get("nic", {})
    if d == "rx":
        return nic.get("rx_packets_phy", 0) - nic.get("rx_out_of_buffer", 0) - nic.get("rx_discards_phy", 0), nic.get("rx_bytes_phy", 0)
    return nic.get("tx_packets_phy", 0), nic.get("tx_bytes_phy", 0)


def counted(r):
    # packets and bytes each monitor reports per direction, scaled by its applied rate
    c = r.get("counts") or {}
    a = r.get("agent")
    out = {}
    if not c:
        return out
    if a == "rfm":
        ex_rx = sum(v for k, v in c.items() if k.startswith("rfm_interface_rx_packets_total.") and not k.endswith(".other"))
        ex_tx = sum(v for k, v in c.items() if k.startswith("rfm_interface_tx_packets_total.") and not k.endswith(".other"))
        exb_rx = sum(v for k, v in c.items() if k.startswith("rfm_interface_rx_bytes_total.") and not k.endswith(".other"))
        exb_tx = sum(v for k, v in c.items() if k.startswith("rfm_interface_tx_bytes_total.") and not k.endswith(".other"))
        out["exact"] = {"rx": (ex_rx, exb_rx), "tx": (ex_tx, exb_tx)}
        out["est"] = {"rx": (c.get("rfm_flow_packets_total.ingress", 0), c.get("rfm_flow_bytes_total.ingress", 0)),
                      "tx": (c.get("rfm_flow_packets_total.egress", 0), c.get("rfm_flow_bytes_total.egress", 0))}
    elif a == "netobserv":
        by = {str(x["d"]): x for x in c.get("by_direction", [])}
        # netobserv's FlowDirection: 0 ingress, 1 egress
        out["est"] = {"rx": (by.get("0", {}).get("packets", 0), by.get("0", {}).get("bytes", 0)),
                      "tx": (by.get("1", {}).get("packets", 0), by.get("1", {}).get("bytes", 0))}
    elif a == "hsflowd":
        # sFlow marks an unknown interface 0x3fffffff. hsflowd's epcap gives received packets an
        # unknown input and the interface as output, the reverse of the sFlow convention, which the
        # 64 KB GRO skbs among them show
        rx = [x for x in c.get("by_port", []) if x["k"].startswith("in1073741823_")]
        tx = [x for x in c.get("by_port", []) if x["k"].endswith("_out1073741823")]
        out["est"] = {"rx": (sum(x["packets"] for x in rx), sum(x["bytes"] for x in rx)),
                      "tx": (sum(x["packets"] for x in tx), sum(x["bytes"] for x in tx))}
    return out


rows = []
for fn in sys.argv[1:]:
    with open(fn) as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                rows.append(json.loads(ln))

base = defaultdict(list)
for r in rows:
    cell, rnd, var = split(r["label"])
    if r["agent"] == "none":
        base[(cell, rnd)].append(r["sys_cores"])

cells = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
for r in rows:
    cell, rnd, var = split(r["label"])
    b = base.get((cell, rnd))
    over = r["sys_cores"] - sum(b) / len(b) if b and r["agent"] != "none" else float("nan")
    prog = r.get("prog") or {}
    secs = r["secs"]
    rxp, _ = wire(r, "rx")
    txp, _ = wire(r, "tx")
    d = cells[cell][var]
    d["n"].append(r["n"])
    d["mpps"].append((rxp + txp) / secs / 1e6)
    d["sys"].append(r["sys_cores"])
    d["over"].append(over)
    d["proc"].append(r["proc_cores"])
    d["ns"].append(prog.get("ns_per_run"))
    d["drops"].append(r.get("ring_drops", 0))
    d["nicdrop"].append(r["nic"].get("rx_out_of_buffer", 0) + r["nic"].get("rx_discards_phy", 0))
    d["mapkb"].append(r.get("map_mem_kb"))
    d["rss"].append(r.get("rss_kb", 0) / 1024)
    col = r.get("collector") or {}
    d["active"].append(col.get("active_flows"))
    d["evict"].append(col.get("forced_evictions_total"))
    d["tables"].append(sum(t.get("entries", 0) for t in r.get("tables", []) if t.get("entries", 0) > 0) if r.get("tables") else None)
    cnt = counted(r)
    for kind in ("exact", "est"):
        if kind in cnt:
            for dirn in ("rx", "tx"):
                wp, wb = wire(r, dirn)
                p, bts = cnt[kind][dirn]
                if wp > 1000:
                    d[f"{kind}_{dirn}_pk"].append(p / wp)
                    d[f"{kind}_{dirn}_by"].append(bts / wb if wb else float("nan"))

for cell in sorted(cells):
    print(f"\n### {cell}\n")
    print("| variant | rounds | N | Mpps | busy cores | over none | proc cores | ns/run | ring drops | nic drops | map KB | RSS MB | entries | rfm active | rfm evictions |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for var, d in sorted(cells[cell].items()):
        def f(k, p=2):
            m, sd, n = ms(d[k])
            return "-" if n == 0 else (f"{m:.{p}f}" if sd == 0 else f"{m:.{p}f} +- {sd:.{p}f}")
        print(f"| {var} | {len(d['sys'])} | {d['n'][0]} | {f('mpps')} | {f('sys')} | {f('over')} | {f('proc', 3)} | {f('ns', 1)} | {f('drops', 0)} | {f('nicdrop', 0)} | {f('mapkb', 0)} | {f('rss', 0)} | {f('tables', 0)} | {f('active', 0)} | {f('evict', 0)} |")
    acc = [(var, d) for var, d in sorted(cells[cell].items()) if any(k.endswith("_pk") for k in d)]
    if acc:
        print("\n| variant | kind | rx packets / wire | rx bytes / wire | tx packets / wire | tx bytes / wire |")
        print("|---|---|---|---|---|---|")
        for var, d in acc:
            for kind in ("exact", "est"):
                if f"{kind}_rx_pk" in d or f"{kind}_tx_pk" in d:
                    def g(k):
                        m, sd, n = ms(d.get(k, []))
                        return "-" if n == 0 else f"{m:.4f} +- {sd:.4f}"
                    print(f"| {var} | {kind} | {g(kind + '_rx_pk')} | {g(kind + '_rx_by')} | {g(kind + '_tx_pk')} | {g(kind + '_tx_by')} |")
