#!/usr/bin/env python3
# ruff: noqa: BLE001
# Tables from fleet.py's files.
#   python3 -I show.py survey DIR
#   python3 -I show.py window DIR
import json
import math
import sys
import time
from pathlib import Path

kind, d = sys.argv[1], Path(sys.argv[2])


def val(r, default=float("nan")):
    try:
        return float(r[0]["value"][1])
    except Exception:
        return default


def ts(t):
    return time.strftime("%m-%d %H:%M", time.gmtime(t)) if t and not math.isnan(t) else "-"


def hostinfo(h):
    info = {"ver": "?", "nproc": -1, "ram": float("nan"), "kernel": "?", "possible": "?", "online": "?",
            "relstart": float("nan"), "active": float("nan"), "drivers": {}, "now": float("nan")}
    if h:
        info["ver"] = h[0].split("rfm-")[-1].split("/")[0]
    if len(h) > 3:
        info["nproc"] = int(h[1]) if h[1].isdigit() else -1
        info["ram"] = int(h[2]) / 1048576 if h[2].isdigit() else float("nan")
        info["kernel"] = h[3]
    for x in h:
        t = x.split()
        if x.startswith("cpus ") and len(t) == 3:
            info["possible"], info["online"] = t[1], t[2]
        elif x.startswith("relstart ") and len(t) == 2:
            info["relstart"] = float(t[1])
        elif x.startswith("active ") and len(t) == 2:
            info["active"] = float(t[1])
        elif x.startswith("driver ") and len(t) == 3:
            info["drivers"][t[1]] = t[2]
    if h and h[-1].isdigit():
        info["now"] = float(h[-1])
    return info


def hourly_sums(v):
    # sums of the hourly instant queries, keyed by "metric|direction" and by metric
    tot, bad, ms, series = {}, 0, 0.0, 0
    for name, byt in (v.get("hourly") or {}).items():
        for cell in byt.values():
            if "error" in cell:
                bad += 1
                continue
            ms += float(cell.get("ms") or 0)
            if name == "est":
                series = max(series, int(cell.get("series") or 0))
            for r in cell["r"]:
                m = r["metric"]
                k = m.get("__name__", name)
                if "direction" in m:
                    k += "|" + m["direction"]
                if name == "series":
                    k = "series"
                    tot[k] = max(tot.get(k, 0.0), float(r["value"][1]))
                else:
                    tot[k] = tot.get(k, 0.0) + float(r["value"][1])
    return tot, bad, ms, series


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


def ncpu(s):
    n = 0
    for p in s.split(","):
        a, _, b = p.partition("-")
        n += int(b or a) - int(a) + 1
    return n


if kind == "window":
    # the footprint table in the columns of the archive of 2026-11-09, then the window per host
    rows = []
    print("| node | vCPU (possible) | RAM GB | RSS avg / max MB | CPU % of a core | flows avg / p95 / max | series max | ring drops | non IP % of rx frames | rx / tx packets against the guest NIC | rx / tx bytes against the guest NIC | driver | window days | forced / folded | restarts | N min / max | scrapes |")
    print("|" + " --- |" * 17)
    for f in sorted(d.glob("*.win.json")):
        v = json.loads(f.read_text())
        i = hostinfo(v["host"])
        w = v["window_s"]
        coll = byname(v["coll_inc"])
        rif = byname(v["rfm_if_inc"], extra="family")
        nic = byname(v["nic_inc"])
        rx = sum(x for k, x in rif.items() if k.startswith("rfm_interface_rx_packets_total"))
        rxo = rif.get("rfm_interface_rx_packets_total.other", 0)
        tx = sum(x for k, x in rif.items() if k.startswith("rfm_interface_tx_packets_total"))
        rxb = sum(x for k, x in rif.items() if k.startswith("rfm_interface_rx_bytes_total"))
        txb = sum(x for k, x in rif.items() if k.startswith("rfm_interface_tx_bytes_total"))
        nan = float("nan")
        nrx, ntx = nic.get("node_network_receive_packets_total", nan), nic.get("node_network_transmit_packets_total", nan)
        nrxb, ntxb = nic.get("node_network_receive_bytes_total", nan), nic.get("node_network_transmit_bytes_total", nan)
        tot, bad, ms, series = hourly_sums(v)
        r = {"node": v["node"], "vcpu": i["nproc"], "possible": ncpu(i["possible"]) if i["possible"] != "?" else -1, "ram": i["ram"],
             "days": w / 86400, "rss_avg": val(v["rss_avg"]) / 1048576, "rss_max": val(v["rss_max"]) / 1048576,
             "cpu": val(v["cpu_s"]) / w * 100, "favg": val(v["flows_avg"]), "fp95": val(v["flows_p95"]), "fmax": val(v["flows_max"]),
             "smax": tot.get("series", nan), "drops": coll.get("rfm_collector_dropped_events_total", nan),
             "forced": coll.get("rfm_collector_forced_evictions_total", nan), "folded": coll.get("rfm_collector_folded_flows_total", nan),
             "nonip": rxo / rx * 100 if rx else nan, "rxr": rx / nrx if nrx else nan, "txr": tx / ntx if ntx else nan,
             "rxbr": rxb / nrxb if nrxb else nan, "txbr": txb / ntxb if ntxb else nan, "driver": i["drivers"].get(v["ifname"], "?"),
             "restarts": val(v["restarts"]), "nmin": val(v["rate_min"]), "nmax": val(v["rate_max"]),
             "up": val(v["up_sum"]), "upn": val(v["up_count"])}
        rows.append(r)
        print(f"| {r['node']} | {r['vcpu']} ({r['possible']}) | {r['ram']:.1f} | {r['rss_avg']:.0f} / {r['rss_max']:.0f} | {r['cpu']:.2f} | {r['favg']:.0f} / {r['fp95']:.0f} / {r['fmax']:.0f} | {r['smax']:.0f} | {r['drops']:.0f} | {r['nonip']:.2f} | {r['rxr']:.4f} / {r['txr']:.4f} | {r['rxbr']:.4f} / {r['txbr']:.4f} | {r['driver']} | {r['days']:.2f} | {r['forced']:.0f} / {r['folded']:.0f} | {r['restarts']:.0f} | {r['nmin']:.0f} / {r['nmax']:.0f} | {r['up']:.0f} of {r['upn']:.0f}, {w / 30:.0f} expected |")
    print()
    for k in ("days", "vcpu", "rss_avg", "rss_max", "cpu", "favg", "fmax", "smax", "drops", "forced", "folded"):
        xs = [r[k] for r in rows]
        print(f"- {k}: median {med(xs):.4g}, min {min(xs):.4g}, max {max(xs):.4g}, hosts {len(xs)}")
    print(f"- cpu under 0.6: {sum(1 for r in rows if r['cpu'] < 0.6)} of {len(rows)}, under 1: {sum(1 for r in rows if r['cpu'] < 1)}")
    print(f"- drops: {[(r['node'], round(r['drops'])) for r in rows if r['drops'] > 0]}")
    for drv in sorted({r["driver"] for r in rows}):
        rs = [r for r in rows if r["driver"] == drv]
        lo = min(min(r["rxr"], r["txr"]) for r in rs)
        hi = max(max(r["rxr"], r["txr"]) for r in rs)
        within = [r["node"] for r in rs if abs(r["rxr"] - 1) <= 0.003 and abs(r["txr"] - 1) <= 0.003]
        above = [(r["node"], round(max(r["rxr"], r["txr"]), 4)) for r in rs if r["node"] not in within]
        print(f"- driver {drv}: {len(rs)} hosts, packets {lo:.4f} to {hi:.4f}, within 0.3% in both directions: {len(within)}, others: {above}")
        print(f"  bytes rx {min(r['rxbr'] for r in rs):.5f} to {max(r['rxbr'] for r in rs):.5f}, tx {min(r['txbr'] for r in rs):.5f} to {max(r['txbr'] for r in rs):.5f}")
        if len(rs) == 1:
            r = rs[0]
            print(f"  {r['node']}: packets rx {r['rxr']:.6f} tx {r['txr']:.6f}, bytes rx {r['rxbr']:.6f} tx {r['txbr']:.6f}")
    print(f"- within 0.3% of the driver in both directions, packets: {sum(1 for r in rows if abs(r['rxr'] - 1) <= 0.003 and abs(r['txr'] - 1) <= 0.003)} of {len(rows)}")
    print(f"- busiest by cpu: {[(r['node'], round(r['cpu'], 2), round(r['favg'])) for r in sorted(rows, key=lambda r: -r['cpu'])[:6]]}")
    rest = sorted(rows, key=lambda r: -r['cpu'])[3:]
    print(f"- flows avg of the others: {min(r['favg'] for r in rest):.0f} to {max(r['favg'] for r in rest):.0f}")

if kind == "tables":
    print("## estimate against exact, per-series differences of the store's samples\n")
    # the sampled packets are rfm_flow_sampled_packets_total, the wire packets of the sampled skbs
    print("| node | hours | failed queries | rx exact IP | est/exact in | est/exact out | sampled packets in | 1/sqrt of them | sampled packets out | series max | query s |")
    print("|" + " --- |" * 11)
    rows = []
    for f in sorted(d.glob("*.win.json")):
        v = json.loads(f.read_text())
        tot, bad, ms, series = hourly_sums(v)
        hours = len((v.get("hourly") or {}).get("est", {}))
        exin, exout = tot.get("rfm_interface_rx_packets_total", 0.0), tot.get("rfm_interface_tx_packets_total", 0.0)
        ein, eout = tot.get("rfm_flow_packets_total|ingress", 0.0), tot.get("rfm_flow_packets_total|egress", 0.0)
        sin, sout = tot.get("rfm_flow_sampled_packets_total|ingress", 0.0), tot.get("rfm_flow_sampled_packets_total|egress", 0.0)
        nan = float("nan")
        r = {"node": v["node"], "hours": hours, "bad": bad, "exin": exin, "rin": ein / exin if exin else nan,
             "rout": eout / exout if exout else nan, "sin": sin, "sout": sout, "inv": 1 / math.sqrt(sin) if sin else nan,
             "invo": 1 / math.sqrt(sout) if sout else nan, "smax": tot.get("series", nan), "ms": ms}
        rows.append(r)
        print(f"| {r['node']} | {hours} | {bad} | {exin:.0f} | {r['rin']:.4f} | {r['rout']:.4f} | {sin:.0f} | {r['inv']:.4f} | {sout:.0f} | {r['smax']:.0f} | {ms / 1000:.0f} |")
    print()
    dev = [abs(r["rin"] - 1) for r in rows] + [abs(r["rout"] - 1) for r in rows]
    print(f"- est/exact in {min(r['rin'] for r in rows):.4f} to {max(r['rin'] for r in rows):.4f}, out {min(r['rout'] for r in rows):.4f} to {max(r['rout'] for r in rows):.4f}, largest deviation {100 * max(dev):.2f}%")
    print(f"- sampled packets in {min(r['sin'] for r in rows):.0f} to {max(r['sin'] for r in rows):.0f}, 1/sqrt {100 * min(r['inv'] for r in rows):.3f} to {100 * max(r['inv'] for r in rows):.3f}%")
    print(f"- sampled packets out {min(r['sout'] for r in rows):.0f} to {max(r['sout'] for r in rows):.0f}, 1/sqrt {100 * min(r['invo'] for r in rows):.3f} to {100 * max(r['invo'] for r in rows):.3f}%")
    print(f"- difference over 1/sqrt, in: {[(r['node'], round((r['rin'] - 1) / r['inv'], 1)) for r in rows]}")
    print(f"- difference over 1/sqrt, out: {[(r['node'], round((r['rout'] - 1) / r['invo'], 1)) for r in rows]}")
    zs = [(r["rin"] - 1) / r["inv"] for r in rows] + [(r["rout"] - 1) / r["invo"] for r in rows]
    print(f"- root mean square of the {len(zs)} differences over 1/sqrt: {math.sqrt(sum(z * z for z in zs) / len(zs)):.2f}")
    print(f"- hosts {len(rows)}, hours {min(r['hours'] for r in rows)} to {max(r['hours'] for r in rows)}, failed queries {sum(r['bad'] for r in rows)}")
    zin = max(rows, key=lambda r: abs((r["rin"] - 1) / r["inv"]))
    zout = max(rows, key=lambda r: abs((r["rout"] - 1) / r["invo"]))
    print(f"- largest difference over 1/sqrt: in {zin['node']} {(zin['rin'] - 1) / zin['inv']:.3f} (ratio {zin['rin']:.5f}), "
          f"out {zout['node']} {(zout['rout'] - 1) / zout['invo']:.3f} (ratio {zout['rout']:.5f})")
    din = max(rows, key=lambda r: abs(r["rin"] - 1))
    dout = max(rows, key=lambda r: abs(r["rout"] - 1))
    print(f"- largest deviation: in {din['node']} {100 * (din['rin'] - 1):.3f}%, out {dout['node']} {100 * (dout['rout'] - 1):.3f}%")
    print(f"- hours by host: {sorted({r['hours'] for r in rows})}, hosts per count: {[(h, sum(1 for r in rows if r['hours'] == h)) for h in sorted({r['hours'] for r in rows})]}")

if kind == "check":
    print("| node | est in: hourly / chain | est out: hourly / chain | samples in: hourly / chain | est in / exact in (hourly) | series | new | restarted | raw samples | query ms | max series per query |")
    print("|" + "---|" * 11)
    for f in sorted(d.glob("*.chain.json")):
        c = json.loads(f.read_text())
        v = json.loads((d / f"{c['node']}.win.json").read_text())
        tot, bad, ms, series = hourly_sums(v)
        ct = c["tot"]

        def ratio(k, tot=tot, ct=ct):
            return tot.get(k, float("nan")) / ct[k] if ct.get(k) else float("nan")
        ex = tot.get("rfm_interface_rx_packets_total", float("nan"))
        print(f"| {c['node']} | {ratio('rfm_flow_packets_total|ingress'):.5f} | {ratio('rfm_flow_packets_total|egress'):.5f} | {ratio('rfm_flow_sampled_packets_total|ingress'):.5f} | {tot.get('rfm_flow_packets_total|ingress', float('nan')) / ex:.4f} | {c['series']} | {c['new']} | {c['restarted']} | {c['samples']} | {ms:.0f} | {series} |")
        print(f"|  | chain est in {ct.get('rfm_flow_packets_total|ingress', 0):.0f}, hourly {tot.get('rfm_flow_packets_total|ingress', 0):.0f}, exact in {ex:.0f}, failed queries {bad}, export rc {c['rc']} |")

if kind == "survey":
    print("| node | rfm | nproc | possible | kernel | N | iface | driver | release since (UTC) | rfm active since | first sample in store | restarts 7d |")
    print("|" + "---|" * 12)
    for f in sorted(d.glob("*.survey.json")):
        v = json.loads(f.read_text())
        i = hostinfo(v["host"])
        ifn = v["iface"][0]["metric"].get("ifname", "?") if isinstance(v["iface"], list) and v["iface"] else "?"
        print(f"| {v['node']} | {i['ver']} | {i['nproc']} | {i['possible']} | {i['kernel']} | {val(v['sample_rate']):.0f} | {ifn} | {i['drivers'].get(ifn, '?')} | {ts(i['relstart'])} | {ts(i['active'])} | {ts(val(v['first_sample']))} | {val(v['restarts_7d']):.0f} |")
