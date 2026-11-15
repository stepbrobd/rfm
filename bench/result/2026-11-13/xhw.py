#!/usr/bin/env python3
# packet shares on the gros (mlx5, 25 GbE) and dahu (i40e, 10 GbE) accuracy runs
# usage: xhw.py PATH_TO_figdata.py
import importlib.util, json, statistics, sys, collections, pathlib
spec = importlib.util.spec_from_file_location("figdata", sys.argv[1])
fd = importlib.util.module_from_spec(spec); spec.loader.exec_module(fd)
here = pathlib.Path(__file__).parent

def wire(r, d):
    n = r["nic"]
    if f"{d}_packets_phy" in n:
        return fd.wire(r, d)
    return sum(n[f"port.{d}_{k}"] for k in ("unicast", "multicast", "broadcast"))

for c in ("gros", "dahu"):
    for ph in ("b1", "b2"):
        g = collections.defaultdict(list); gbps = collections.defaultdict(list)
        for l in open(here / c / f"{ph}.jsonl"):
            r = json.loads(l)
            cell, rnd, var = fd.split(r["label"])
            d = cell[:2]
            w = wire(r, d)
            for kind, v in fd.counted(r, d).items():
                g[(cell, var, kind)].append(100 * v / w)
            bk = "port." + d + "_bytes" if "port.rx_bytes" in r["nic"] else d + "_bytes_phy"
            gbps[cell].append(r["nic"][bk] * 8 / r["secs"] / 1e9)
        print(f"== {c} {ph}")
        for cell in sorted({k[0] for k in g}):
            row = [f"{cell:28s} {statistics.mean(gbps[cell]):5.1f} Gb/s"]
            for var, kind in (("rfm_acc", "exact"), ("rfm_acc", "est"), ("netobserv", "est"), ("hsflowd", "est")):
                xs = g.get((cell, var, kind), [])
                row.append(f"{var}.{kind} {statistics.mean(xs):7.2f} [{min(xs):.2f},{max(xs):.2f}] n={len(xs)}" if xs else f"{var}.{kind} -")
            print("  ".join(row))
