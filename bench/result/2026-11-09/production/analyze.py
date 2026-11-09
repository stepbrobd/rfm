#!/usr/bin/env python3
# ruff: noqa: B023, BLE001, C408
# Tables from scrape.py's chained deltas and vm.py's window extraction.
#   python3 -I analyze.py DIR
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

d = Path(sys.argv[1])


def val(r, default=float("nan")):
    try:
        return float(r[0]["value"][1])
    except Exception:
        return default


def byname(rs, key="__name__", extra=None):
    out = {}
    if not isinstance(rs, list):
        return out
    for r in rs:
        k = r["metric"].get(key, "")
        if extra:
            k += "." + r["metric"].get(extra, "")
        out[k] = float(r["value"][1])
    return out


def med(xs):
    xs = sorted(x for x in xs if not math.isnan(x))
    if not xs:
        return float("nan")
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


print("## window extraction (VictoriaMetrics, single series only)\n")
print("| node | ver | vcpu | ram GB | days | rss avg MB | rss max MB | cg cur MB | cpu % core | flows avg | flows p95 | flows max | series max | series/flows | drops | drops/Mev | forced | folded | non-IP rx % | rx/nic pk | tx/nic pk | rx/nic by | tx/nic by | maps KB |")
print("|" + "---|" * 25)
rows = []
for f in sorted(d.glob("*.vm.json")):
    v = json.loads(f.read_text())
    h = v["host"]
    ver = h[0].split("rfm-")[-1].split("/")[0] if h else "?"
    vcpu = int(h[1]) if len(h) > 1 and h[1].isdigit() else -1
    ram = int(h[2]) / 1048576 if len(h) > 2 and h[2].isdigit() else float("nan")
    cg = int(h[4]) / 1048576 if len(h) > 4 and h[4].lstrip("-").isdigit() and int(h[4]) > 0 else float("nan")
    maps = float("nan")
    for x in h:
        if x.startswith("maps "):
            maps = float(x.split()[2]) / 1024
    w = v["window_s"]
    coll = byname(v["coll_inc"])
    rif = byname(v["rfm_if_inc"], extra="family")
    nic = byname(v["nic_inc"])
    rx = sum(x for k, x in rif.items() if k.startswith("rfm_interface_rx_packets_total"))
    rxo = rif.get("rfm_interface_rx_packets_total.other", 0)
    tx = sum(x for k, x in rif.items() if k.startswith("rfm_interface_tx_packets_total"))
    rxb = sum(x for k, x in rif.items() if k.startswith("rfm_interface_rx_bytes_total"))
    txb = sum(x for k, x in rif.items() if k.startswith("rfm_interface_tx_bytes_total"))
    nrx = nic.get("node_network_receive_packets_total", float("nan"))
    ntx = nic.get("node_network_transmit_packets_total", float("nan"))
    nrxb = nic.get("node_network_receive_bytes_total", float("nan"))
    ntxb = nic.get("node_network_transmit_bytes_total", float("nan"))
    ser = [float(x[1]) for s in (v["series_hourly"] if isinstance(v["series_hourly"], list) else []) for x in s["values"]]
    smax = max(ser) if ser else float("nan")
    created = coll.get("rfm_collector_created_flows_total", float("nan"))
    drops = coll.get("rfm_collector_dropped_events_total", float("nan"))
    fmax = val(v["flows_max"])
    row = dict(node=v["node"], ver=ver, vcpu=vcpu, ram=ram, days=w / 86400,
               rss_avg=val(v["rss_avg"]) / 1048576, rss_max=val(v["rss_max"]) / 1048576, cg=cg,
               cpu=val(v["cpu_s"]) / w * 100, favg=val(v["flows_avg"]), fp95=val(v["flows_p95"]), fmax=fmax,
               smax=smax, sf=smax / fmax if fmax else float("nan"), drops=drops,
               forced=coll.get("rfm_collector_forced_evictions_total", float("nan")),
               folded=coll.get("rfm_collector_folded_flows_total", float("nan")),
               nonip=rxo / rx * 100 if rx else float("nan"),
               rxr=rx / nrx if nrx else float("nan"), txr=tx / ntx if ntx else float("nan"),
               rxbr=rxb / nrxb if nrxb else float("nan"), txbr=txb / ntxb if ntxb else float("nan"), maps=maps)
    rows.append(row)
    print(f"| {row['node']} | {ver} | {vcpu} | {ram:.1f} | {row['days']:.1f} | {row['rss_avg']:.0f} | {row['rss_max']:.0f} | {cg:.0f} | {row['cpu']:.2f} | {row['favg']:.0f} | {row['fp95']:.0f} | {fmax:.0f} | {smax:.0f} | {row['sf']:.2f} | {drops:.0f} | - | {row['forced']:.0f} | {row['folded']:.0f} | {row['nonip']:.2f} | {row['rxr']:.4f} | {row['txr']:.4f} | {row['rxbr']:.4f} | {row['txbr']:.4f} | {maps:.0f} |")
if rows:
    print()
    for k in ("rss_avg", "rss_max", "cpu", "favg", "fmax", "smax", "sf", "maps"):
        xs = [r[k] for r in rows]
        print(f"- {k}: median {med(xs):.3g}, min {min(xs):.3g}, max {max(xs):.3g}")

print("\n## estimate against exact, chained direct scrape deltas\n")
print("| node | hours | intervals | rx exact IP | est/exact in | est/exact out | samples in | 1/sqrt(samples) | series avg | new/min | vanished/min | restarted/min | drops |")
print("|" + "---|" * 13)
for f in sorted(d.glob("*.jsonl")):
    recs = [json.loads(x) for x in f.read_text().splitlines() if x.strip()]
    if not recs:
        continue
    tot = defaultdict(float)
    secs = 0.0
    ser = []
    new = van = rst = 0
    drops = 0.0
    for r in recs:
        secs += r["dt"]
        for k, x in r["flow"].items():
            name, dirn, _ = k.split("|")
            tot[f"{name}|{dirn}"] += x
        for k, x in r["iface"].items():
            name, fam, _ = k.split("|")
            if fam != "other":
                tot[name] += x
        ser.append(r["series"])
        new += r["new"]
        van += r["vanished"]
        rst += r["restarted"]
        drops += r["single"].get("rfm_collector_dropped_events_total", 0)
    exin = tot["rfm_interface_rx_packets_total"]
    exout = tot["rfm_interface_tx_packets_total"]
    ein = tot["rfm_flow_packets_total|ingress"]
    eout = tot["rfm_flow_packets_total|egress"]
    sin = tot["rfm_flow_sampled_packets_total|ingress"]
    m = secs / 60
    print(f"| {f.stem} | {secs / 3600:.2f} | {len(recs)} | {exin:.0f} | {ein / exin if exin else float('nan'):.4f} | {eout / exout if exout else float('nan'):.4f} | {sin:.0f} | {1 / math.sqrt(sin) if sin else float('nan'):.4f} | {sum(ser) / len(ser):.0f} | {new / m:.0f} | {van / m:.0f} | {rst / m:.0f} | {drops:.0f} |")

print("\n## VictoriaMetrics increase() against the chained deltas, same window\n")
print("| node | inc est in / delta est in | inc est out / delta est out | inc est/inc exact in | delta est/delta exact in |")
print("|---|---|---|---|---|")
for f in sorted(d.glob("*.bias.json")):
    b = json.loads(f.read_text())
    n = b["node"]
    recs = [json.loads(x) for x in (d / f"{n}.jsonl").read_text().splitlines() if x.strip()]
    tot = defaultdict(float)
    for r in recs:
        for k, x in r["flow"].items():
            name, dirn, _ = k.split("|")
            tot[f"{name}|{dirn}"] += x
        for k, x in r["iface"].items():
            name, fam, _ = k.split("|")
            if fam != "other":
                tot[name] += x
    inc = byname(b["flow_inc"], key="direction")
    ifi = byname(b["if_inc"])
    di, do = tot["rfm_flow_packets_total|ingress"], tot["rfm_flow_packets_total|egress"]
    ei = tot["rfm_interface_rx_packets_total"]
    ii = ifi.get("rfm_interface_rx_packets_total", float("nan"))
    print(f"| {n} | {inc.get('ingress', float('nan')) / di if di else float('nan'):.4f} | {inc.get('egress', float('nan')) / do if do else float('nan'):.4f} | {inc.get('ingress', float('nan')) / ii if ii else float('nan'):.4f} | {di / ei if ei else float('nan'):.4f} |")

print("\n## samples per flow from the live tables (M/N per flow record)\n")
print("| node | snapshots | flows | p50 | p90 | p99 | max | flows >= 10 | flows >= 100 | est packets in flows >= 10 | est packets in flows >= 100 |")
print("|---|---|---|---|---|---|---|---|---|---|---|")
allf = []
for f in sorted(d.glob("*.flowsize.json")):
    v = json.loads(f.read_text())
    fl = v["flows"]
    if not fl:
        continue
    allf += fl
    ps = sorted(x[0] for x in fl)
    q = lambda p: ps[min(len(ps) - 1, int(p * len(ps)))]
    est = sum(x[1] for x in fl)
    e10 = sum(x[1] for x in fl if x[0] >= 10)
    e100 = sum(x[1] for x in fl if x[0] >= 100)
    print(f"| {v['node']} | {v['snapshots']} | {len(ps)} | {q(0.5)} | {q(0.9)} | {q(0.99)} | {ps[-1]} | {sum(p >= 10 for p in ps) / len(ps):.3f} | {sum(p >= 100 for p in ps) / len(ps):.4f} | {e10 / est if est else float('nan'):.3f} | {e100 / est if est else float('nan'):.3f} |")
if allf:
    ps = sorted(x[0] for x in allf)
    est = sum(x[1] for x in allf)
    print(f"\nfleet: {len(ps)} flows, median {ps[len(ps) // 2]} samples, {sum(p >= 10 for p in ps) / len(ps):.3f} of flows and {sum(x[1] for x in allf if x[0] >= 10) / est:.3f} of estimated packets in flows of 10 or more samples, {sum(x[1] for x in allf if x[0] >= 100) / est:.3f} in flows of 100 or more")
