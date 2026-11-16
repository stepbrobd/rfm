#!/usr/bin/env python3
# ruff: noqa: BLE001, PLW1510
# Read-only extraction from the hosts' own VictoriaMetrics, for the deployment section of the
# imc27 paper. It never scrapes an rfm agent: a second scraper takes the zero sample of new
# rollup tuples away from the store (cahier, rollup churn). Every query goes over ssh to the
# store on loopback.
#
#   python3 -I fleet.py survey --out DIR host ...
#   python3 -I fleet.py window --out DIR --plan FILE      (FILE: "host start end" per line, epoch s)
#   python3 -I fleet.py chain  --out DIR --plan FILE
#
# survey: release, start times, CPUs and sampling rate of each host.
# window: footprint and counters over each host's window, and the flow estimates summed hour by
#   hour with increase_pure. On a host with much label churn each of these hourly queries reads
#   tens of thousands of series and keeps the store busy for seconds: on the busiest host of
#   2026-11-16 the 146 hours took 12 minutes of one core. Do not add queries over the rollup
#   series there without need.
# chain: the same sums from the store's raw samples, as a check of the hourly queries.
# edges: the raw samples of the exact IP counters around a window, for flowcheck.py.
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# directory of the ssh control sockets
CM = os.environ.get("FLEET_CM", "/tmp")
SSH = ["ssh", "-C", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ControlMaster=auto",
       "-o", f"ControlPath={CM}/cm-%C", "-o", "ControlPersist=10m"]
VM = "http://[::1]:8428"
FLOW = '{__name__=~"rfm_flow_(packets|sampled_packets)_total"}'
IFACE = '{__name__=~"rfm_interface_(rx|tx)_packets_total",family!="other"}'


def sh(node, cmd, timeout=180):
    r = subprocess.run([*SSH, node, "bash", "-s"], input=cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout


def q(node, expr, t=None):
    p = {"query": expr}
    if t:
        p["time"] = str(t)
    out = sh(node, f"curl -s --max-time 100 '{VM}/api/v1/query?{urllib.parse.urlencode(p)}'")
    try:
        return json.loads(out)["data"]["result"]
    except Exception:
        return {"error": out[:300]}


def qr(node, expr, start, end, step):
    p = {"query": expr, "start": str(start), "end": str(end), "step": step}
    out = sh(node, f"curl -s --max-time 100 '{VM}/api/v1/query_range?{urllib.parse.urlencode(p)}'")
    try:
        return json.loads(out)["data"]["result"]
    except Exception:
        return {"error": out[:300]}


def hourly(node, exprs, start, end):
    # one instant query per hour and expression in a single ssh session, in sequence, so that no
    # query spans more than an hour of the churning rollup series and the store serves one at a time
    lines = []
    for name, expr in exprs.items():
        for t in range(start + 3600, end + 1, 3600):
            url = f"{VM}/api/v1/query?" + urllib.parse.urlencode({"query": expr, "time": str(t)})
            lines.append(f"printf '%s %s ' {name} {t}; curl -s --max-time 100 '{url}'; echo")
    out = sh(node, "\n".join(lines) + "\n", timeout=7200)
    res = defaultdict(dict)
    for ln in out.splitlines():
        t = ln.split(" ", 2)
        if len(t) < 3:
            continue
        try:
            body = json.loads(t[2])
            res[t[0]][t[1]] = {"r": body["data"]["result"], "ms": body.get("stats", {}).get("executionTimeMsec"),
                               "series": body.get("stats", {}).get("seriesFetched")}
        except Exception:
            res[t[0]][t[1]] = {"error": t[2][:200]}
    return res


HOST = """
readlink -f /run/current-system/sw/bin/rfm
nproc; awk '/MemTotal/{print $2}' /proc/meminfo; uname -r
echo "cpus $(cat /sys/devices/system/cpu/possible) $(cat /sys/devices/system/cpu/online)"
cur=$(readlink -f /run/current-system/sw/bin/rfm | cut -d- -f2-); first=""
for l in $(ls -d /nix/var/nix/profiles/system-*-link | sort -t- -k2 -n -r); do
  [ "$(readlink -f $l/sw/bin/rfm | cut -d- -f2-)" = "$cur" ] || break; first=$(stat -c %Y $l); done
echo "relstart $first"
echo "active $(date -d "$(systemctl show rfm -p ActiveEnterTimestamp --value)" +%s)"
for f in /sys/class/net/*/device/driver; do echo "driver $(echo $f | cut -d/ -f5) $(basename $(readlink -f $f))"; done
date +%s
"""


def survey(node):
    host = sh(node, HOST).splitlines()
    return {
        "node": node, "host": host,
        "sample_rate": q(node, "rfm_bpf_sample_rate"),
        "proc_start": q(node, 'process_start_time_seconds{job="rfm"}'),
        "first_sample": q(node, 'min(tfirst_over_time(rfm_interface_rx_packets_total[30d]))'),
        "restarts_7d": q(node, 'changes(process_start_time_seconds{job="rfm"}[7d])'),
        "iface": q(node, "rfm_interface_rx_packets_total"),
        "cpus_store": q(node, 'count(count by (cpu) (node_cpu_seconds_total))'),
    }


def window(node, start, end, flows=True):
    w = end - start
    W = f"{w}s"
    iface = q(node, "rfm_interface_rx_packets_total", end)
    ifn = iface[0]["metric"].get("ifname", "eth0") if isinstance(iface, list) and iface else "eth0"
    res = {
        "node": node, "start": start, "end": end, "window_s": w, "ifname": ifn,
        "host": sh(node, HOST).splitlines(),
        "rss_avg": q(node, f'avg_over_time(process_resident_memory_bytes{{job="rfm"}}[{W}])', end),
        "rss_max": q(node, f'max_over_time(process_resident_memory_bytes{{job="rfm"}}[{W}])', end),
        "cpu_s": q(node, f'increase(process_cpu_seconds_total{{job="rfm"}}[{W}])', end),
        "restarts": q(node, f'changes(process_start_time_seconds{{job="rfm"}}[{W}])', end),
        "up_count": q(node, f'count_over_time(up{{job="rfm"}}[{W}])', end),
        "up_sum": q(node, f'sum_over_time(up{{job="rfm"}}[{W}])', end),
        "flows_avg": q(node, f"avg_over_time(rfm_collector_active_flows[{W}])", end),
        "flows_max": q(node, f"max_over_time(rfm_collector_active_flows[{W}])", end),
        "flows_p95": q(node, f"quantile_over_time(0.95, rfm_collector_active_flows[{W}])", end),
        "rate_max": q(node, f"max_over_time(rfm_bpf_sample_rate[{W}])", end),
        "rate_min": q(node, f"min_over_time(rfm_bpf_sample_rate[{W}])", end),
        "coll_inc": q(node, f'increase({{__name__=~"rfm_collector_(created_flows|dropped_events|folded_flows|forced_evictions)_total"}}[{W}]) keep_metric_names', end),
        "errors_inc": q(node, f"increase(rfm_errors_total[{W}])", end),
        "rfm_if_inc": q(node, f'increase({{__name__=~"rfm_interface_.*_total"}}[{W}]) keep_metric_names', end),
        "nic_inc": q(node, f'increase({{__name__=~"node_network_(receive|transmit)_(packets|bytes|drop)_total",device="{ifn}"}}[{W}]) keep_metric_names', end),
    }
    if flows:
        # increase_pure counts a series that is new in the hour from zero and any other series from
        # its last sample before the hour, for the estimates and the exact counters alike
        # the run of 2026-11-16 also asked for count(rfm_flow_packets_total) per hour. On the host
        # with the most label churn that query took about 3 s per hour, and it was stopped there
        # after 3 hours, so that host's "series max" comes from 3 hours. The query is left out here.
        res["hourly"] = hourly(node, {
            "est": f"sum by (__name__, direction) (increase_pure({FLOW}[1h]) keep_metric_names)",
            "exact": f"sum by (__name__) (increase_pure({IFACE}[1h]) keep_metric_names)",
        }, start, end)
    return res


def chain(node, start, end, out):
    # chained differences of the store's raw samples: a series with a sample at or before the start
    # counts from that sample, a series new in the window counts from zero, a value below the last
    # one restarted from zero
    sel = urllib.parse.urlencode({"match[]": FLOW, "start": str(start - 900), "end": str(end)})
    p = subprocess.Popen([*SSH, node, f"curl -s --max-time 900 '{VM}/api/v1/export?{sel}'"],
                         stdout=subprocess.PIPE, text=True)
    tot = defaultdict(float)
    series = new = restarted = samples = 0
    for ln in p.stdout:
        ln = ln.strip()
        if not ln:
            continue
        s = json.loads(ln)
        m = s["metric"]
        key = f"{m['__name__']}|{m.get('direction', '')}"
        prev, acc, inside = None, 0.0, False
        for v, t in zip(s["values"], s["timestamps"]):
            if v is None:
                continue
            samples += 1
            if t / 1000 <= start:
                prev = v
                continue
            inside = True
            if prev is None:
                acc += v
                new += 1
            elif v < prev:
                acc += v
                restarted += 1
            else:
                acc += v - prev
            prev = v
        if inside:
            series += 1
        tot[key] += acc
    p.wait()
    rec = {"node": node, "start": start, "end": end, "tot": tot, "series": series, "new": new,
           "restarted": restarted, "samples": samples, "rc": p.returncode}
    (out / f"{node}.chain.json").write_text(json.dumps(rec))
    return rec


def edges(node, start, end):
    # the raw samples of the exact IP counters around a window, to read them at any instant in it
    p = urllib.parse.urlencode({"match[]": IFACE, "start": str(start - 120), "end": str(end + 120)})
    out = sh(node, f"curl -s --max-time 100 '{VM}/api/v1/export?{p}'")
    series = []
    for ln in out.splitlines():
        if not ln.startswith("{"):
            continue
        s = json.loads(ln)
        m = s["metric"]
        series.append({"name": m["__name__"], "family": m.get("family", ""), "ifname": m.get("ifname", ""),
                       "t": s["timestamps"], "v": s["values"]})
    return {"node": node, "start": start, "end": end, "series": series}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["survey", "window", "chain", "edges"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--plan")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--no-flows", action="store_true")
    ap.add_argument("nodes", nargs="*")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    plan = {}
    if a.plan:
        for ln in Path(a.plan).read_text().splitlines():
            t = ln.split()
            if len(t) == 3 and not ln.startswith("#"):
                plan[t[0]] = (int(t[1]), int(t[2]))
    nodes = a.nodes or list(plan)

    def one(n):
        t0 = time.time()
        try:
            if a.cmd == "survey":
                (out / f"{n}.survey.json").write_text(json.dumps(survey(n)))
            elif a.cmd == "window":
                (out / f"{n}.win.json").write_text(json.dumps(window(n, *plan[n], flows=not a.no_flows)))
            elif a.cmd == "edges":
                (out / f"{n}.edges.json").write_text(json.dumps(edges(n, *plan[n])))
            else:
                chain(n, *plan[n], out)
        except Exception as e:
            print(f"{n}: failed: {e}", file=sys.stderr)
            return
        print(f"{n}: {time.time() - t0:.1f} s", file=sys.stderr)

    with ThreadPoolExecutor(a.jobs) as ex:
        list(ex.map(one, nodes))


if __name__ == "__main__":
    main()
