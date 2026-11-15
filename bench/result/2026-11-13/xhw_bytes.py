#!/usr/bin/env python3
# byte shares against the port byte counters, offload cases (b1), per cluster
# usage: xhw_bytes.py DIR...   (each DIR holds b1.jsonl)
import json, statistics, sys, collections, re

def port(n, d):
    if f"{d}_bytes_phy" in n:
        return n[f"{d}_bytes_phy"], n[f"{d}_packets_phy"]
    return n[f"port.{d}_bytes"], sum(n[f"port.{d}_{k}"] for k in ("unicast", "multicast", "broadcast"))

def mon(r, d):
    c = r.get("counts") or {}
    a = r["agent"]
    if a == "rfm":
        pre = f"rfm_interface_{d}_bytes_total."
        return {"exact": sum(v for k, v in c.items() if k.startswith(pre)),
                "est": c.get("rfm_flow_bytes_total." + ("ingress" if d == "rx" else "egress"), 0)}
    if a == "netobserv":
        by = {str(x["d"]): x for x in c.get("by_direction", [])}
        return {"est": by.get("0" if d == "rx" else "1", {}).get("bytes", 0)}
    if a == "hsflowd":
        tot = 0
        for x in c.get("by_port", []):
            inn = x["k"].split("_")[0] == "in1073741823"
            if (d == "rx") == inn:
                tot += x["bytes"]
        return {"est": tot}
    return {}

for dname in sys.argv[1:]:
    g = collections.defaultdict(list)
    for l in open(f"{dname}/b1.jsonl"):
        r = json.loads(l)
        m = re.match(r"^(.*?) r(\d+) (\S+)$", r["label"])
        cell, var = m.group(1), m.group(3)
        d = cell[:2]
        pb, pp = port(r["nic"], d)
        for kind, v in mon(r, d).items():
            # the port counts 4 bytes of FCS per frame, taken out here
            g[(cell, var, kind)].append(100 * v / (pb - 4 * pp))
            g[(cell, var, kind + "_fcs")].append(100 * v / pb)
    print("==", dname, "(percent of port bytes less FCS, in brackets against raw port bytes)")
    for cell in sorted({k[0] for k in g}):
        row = [f"{cell:9s}"]
        for var, kind in (("rfm_acc", "exact"), ("rfm_acc", "est"), ("netobserv", "est"), ("hsflowd", "est")):
            xs, ys = g.get((cell, var, kind)), g.get((cell, var, kind + "_fcs"))
            row.append(f"{var}.{kind} {statistics.mean(xs):7.3f} ({statistics.mean(ys):7.3f}) n={len(xs)}" if xs else f"{var}.{kind} -")
        print("  ".join(row))
