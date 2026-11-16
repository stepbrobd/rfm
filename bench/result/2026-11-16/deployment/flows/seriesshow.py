#!/usr/bin/env python3
# The tables of fleet.py series: per host the share of the window's estimated packets in label
# tuples and in remote ASes with 100 (and 4500) or more sampled packets in the window. The remote
# AS is the source AS of received and the destination AS of sent packets. "named" leaves out the
# packets whose remote address has no AS, "no AS" is their share.
#   python3 -I seriesshow.py DIR
import json
import sys
from pathlib import Path

NAMES = ("den", "tuple100", "as100_in", "as100_out", "unk_in", "unk_out", "asn100_in", "asn100_out", "asn4500_in", "asn4500_out",
         "nasn_in", "nasn_out", "nasn100_in", "nasn100_out", "nasn4500_in", "nasn4500_out")
KEYS = ("den", "tuple", "group", "asn100", "asn4500", "unk")


def med(v):
    s = sorted(v)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


d = Path(sys.argv[1])
print("| node | window s | est in | est out | tuples 100+ | AS groups 100+ | named ASes 100+ | named ASes 4500+ | no AS | "
      "named ASes in / out | with 100+ in / out | with 4500+ in / out | query s | errors |")
print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
tot = dict.fromkeys(KEYS, 0.0)
rows = []
for f in sorted(d.glob("*.series.json")):
    v = json.loads(f.read_text())
    q = v["q"]

    def by_dir(name, q=q):
        return {r["metric"].get("direction", ""): float(r["value"][1]) for r in (q.get(name, {}).get("r") or [])}

    def one(name, q=q):
        r = q.get(name, {}).get("r") or []
        return float(r[0]["value"][1]) if r else 0.0

    den, tup = by_dir("den"), by_dir("tuple100")
    din, dout = den.get("ingress", 0.0), den.get("egress", 0.0)
    x = {"den": din + dout, "tuple": tup.get("ingress", 0.0) + tup.get("egress", 0.0), "group": one("as100_in") + one("as100_out"),
         "asn100": one("asn100_in") + one("asn100_out"), "asn4500": one("asn4500_in") + one("asn4500_out"),
         "unk": one("unk_in") + one("unk_out")}
    errs = [k for k, y in q.items() if y.get("error")] + [k for k in NAMES if k not in q]
    ms = sum(float(y.get("ms") or 0) for y in q.values())
    for k in KEYS:
        tot[k] += x[k]
    r = {k: x[k] / x["den"] if x["den"] else float("nan") for k in KEYS}
    rows.append(r)
    print(f"| {v['node']} | {v['end'] - v['start']} | {din:.0f} | {dout:.0f} | {r['tuple']:.4f} | {r['group']:.4f} | {r['asn100']:.4f} | "
          f"{r['asn4500']:.4f} | {r['unk']:.4f} | {one('nasn_in'):.0f} / {one('nasn_out'):.0f} | "
          f"{one('nasn100_in'):.0f} / {one('nasn100_out'):.0f} | {one('nasn4500_in'):.0f} / {one('nasn4500_out'):.0f} | "
          f"{ms / 1000:.1f} | {' '.join(errs) or 'none'} |")
if rows:
    print(f"\n- {len(rows)} hosts, both directions, {tot['den']:.0f} estimated packets")
    for k, what in (("tuple", "label tuples with 100+ sampled packets"), ("group", "remote AS groups with 100+, the packets without an AS as one group"),
                    ("asn100", "named remote ASes with 100+ sampled packets"), ("asn4500", "named remote ASes with 4500+ sampled packets"),
                    ("unk", "packets whose remote address has no AS")):
        s = sorted(r[k] for r in rows)
        print(f"- {what}: pooled {tot[k] / tot['den']:.4f} of the estimated packets, per host {s[0]:.4f} to {s[-1]:.4f}, median {med(s):.4f}")
