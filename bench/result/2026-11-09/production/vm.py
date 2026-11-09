#!/usr/bin/env python3
# ruff: noqa: BLE001, PLW1510
# Read-only VictoriaMetrics extraction per node over the window since the running rfm started
# (or 14 days, whichever is shorter). Queries only single series counters and gauges, never
# increase() over the churning rollups, see the rollup churn note in cahier.
#
#   python3 -I vm.py --out DIR node ...
import argparse
import json
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def sh(node, cmd, timeout=120):
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                        "-o", "ControlMaster=auto", "-o", "ControlPath=/tmp/claude-1000/fleet-%r@%h",
                        "-o", "ControlPersist=15m", node, "bash", "-s"],
                       input=cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout


def q(node, expr, t=None):
    p = {"query": expr}
    if t:
        p["time"] = str(t)
    url = "http://[::1]:8428/api/v1/query?" + urllib.parse.urlencode(p)
    out = sh(node, f"curl -s --max-time 100 '{url}'")
    try:
        return json.loads(out)["data"]["result"]
    except Exception:
        return {"error": out[:300]}


def qr(node, expr, start, end, step):
    p = {"query": expr, "start": str(start), "end": str(end), "step": step}
    url = "http://[::1]:8428/api/v1/query_range?" + urllib.parse.urlencode(p)
    out = sh(node, f"curl -s --max-time 100 '{url}'")
    try:
        return json.loads(out)["data"]["result"]
    except Exception:
        return {"error": out[:300]}


def one(node):
    now = int(time.time())
    host = sh(node, """
readlink -f $(systemctl show rfm -p ExecStart --value | sed -E 's/.*path=([^ ;]*).*/\\1/')
nproc; awk '/MemTotal/{print $2}' /proc/meminfo; uname -r
cat /sys/fs/cgroup/system.slice/rfm.service/memory.current 2>/dev/null || echo -1
cat /sys/fs/cgroup/system.slice/rfm.service/memory.peak 2>/dev/null || echo -1
ip -o link show | awk -F': ' '{print $2}' | tr '\\n' ' '; echo
for f in /sys/class/net/*/device/features; do echo "$f $(cat $f)"; done
for f in /sys/class/net/*/device/driver; do echo "$f $(basename $(readlink -f $f))"; done
cur=$(readlink -f /run/current-system/sw/bin/rfm | cut -d- -f2-); first=""
for l in $(ls -d /nix/var/nix/profiles/system-*-link | sort -t- -k2 -n -r); do
  [ "$(readlink -f $l/sw/bin/rfm | cut -d- -f2-)" = "$cur" ] || break; first=$(stat -c %Y $l); done
echo "relstart $first"
p=$(systemctl show rfm -p MainPID --value)
sudo -n bash -c "for f in /proc/$p/fdinfo/*; do id=\\$(awk '/^map_id:/{print \\$2}' \\$f); [ -n \"\\$id\" ] && echo \\$id \\$(awk '/^memlock:/{print \\$2}' \\$f); done" | sort -u -k1,1 | awk '{s+=$2} END {print "maps", NR, s}'
echo "cpus $(cat /sys/devices/system/cpu/possible) $(cat /sys/devices/system/cpu/online)"
""").splitlines()
    rel = [x for x in host if x.startswith("relstart ")]
    try:
        start = int(rel[0].split()[1])
    except Exception:
        start = now - 3600
    # the first scrape after the switch, and never past the 14 day retention
    start = max(start + 300, now - 14 * 86400 + 600)
    w = now - start
    W = f"{w}s"
    iface = q(node, 'rfm_interface_rx_packets_total')
    ifn = iface[0]["metric"].get("ifname", "eth0") if isinstance(iface, list) and iface else "eth0"
    res = {
        "node": node, "now": now, "start": start, "window_s": w, "host": host, "ifname": ifn,
        "rss_avg": q(node, f'avg_over_time(process_resident_memory_bytes{{job="rfm"}}[{W}])'),
        "rss_max": q(node, f'max_over_time(process_resident_memory_bytes{{job="rfm"}}[{W}])'),
        "cpu_s": q(node, f'increase(process_cpu_seconds_total{{job="rfm"}}[{W}])'),
        "flows_avg": q(node, f'avg_over_time(rfm_collector_active_flows[{W}])'),
        "flows_max": q(node, f'max_over_time(rfm_collector_active_flows[{W}])'),
        "flows_p95": q(node, f'quantile_over_time(0.95, rfm_collector_active_flows[{W}])'),
        "coll_inc": q(node, f'increase({{__name__=~"rfm_collector_(created_flows|dropped_events|folded_flows|forced_evictions)_total"}}[{W}]) keep_metric_names'),
        "errors_inc": q(node, f'increase(rfm_errors_total[{W}])'),
        "ipfix_inc": q(node, f'increase({{__name__=~"rfm_ipfix_.*_total"}}[{W}]) keep_metric_names'),
        "rfm_if_inc": q(node, f'increase({{__name__=~"rfm_interface_.*_total"}}[{W}]) keep_metric_names'),
        "nic_inc": q(node, f'increase({{__name__=~"node_network_(receive|transmit)_(packets|bytes|drop)_total",device="{ifn}"}}[{W}]) keep_metric_names'),
        "pps_hourly": qr(node, 'sum(rate({__name__=~"rfm_interface_(rx|tx)_packets_total"}[1h]))', start + 3600, now, "1h"),
        "series_hourly": qr(node, 'count(rfm_flow_bytes_total)', start, now, "1h"),
        "flows_hourly_max": qr(node, 'max_over_time(rfm_collector_active_flows[1h])', start + 3600, now, "1h"),
        "drops_hourly": qr(node, 'increase(rfm_collector_dropped_events_total[1h])', start + 3600, now, "1h"),
        "nic_ratio_hourly": qr(node, f'sum(increase({{__name__=~"rfm_interface_rx_packets_total"}}[1h])) / sum(increase(node_network_receive_packets_total{{device="{ifn}"}}[1h]))', start + 3600, now, "1h"),
        "nic_ratio_tx_hourly": qr(node, f'sum(increase({{__name__=~"rfm_interface_tx_packets_total"}}[1h])) / sum(increase(node_network_transmit_packets_total{{device="{ifn}"}}[1h]))', start + 3600, now, "1h"),
    }
    return res


# VictoriaMetrics increase() over the rollups for the scrape window, against the chained deltas
def bias(node, t0, t1):
    w = int(t1 - t0)
    return {
        "node": node, "t0": t0, "t1": t1,
        "flow_inc": q(node, f'sum by (direction) (increase(rfm_flow_packets_total[{w}s]))', t1),
        "flow_inc_bytes": q(node, f'sum by (direction) (increase(rfm_flow_bytes_total[{w}s]))', t1),
        "if_inc": q(node, f'sum by (__name__) (increase({{__name__=~"rfm_interface_(rx|tx)_packets_total",family!="other"}}[{w}s]) keep_metric_names)', t1),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--bias", action="store_true", help="only the increase() check over each node's scrape window")
    ap.add_argument("nodes", nargs="+")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if a.bias:
        for n in a.nodes:
            recs = [json.loads(x) for x in (out / f"{n}.jsonl").read_text().splitlines() if x.strip()]
            if not recs:
                continue
            # whole minutes inside the chain, so the 30 s scrapes of VictoriaMetrics fall in both
            (out / f"{n}.bias.json").write_text(json.dumps(bias(n, int(recs[0]["t0"]), int(recs[-1]["t1"]))))
            print(n, file=sys.stderr)
        return
    with ThreadPoolExecutor(8) as ex:
        for r in ex.map(lambda n: (n, one(n)), a.nodes):
            n, res = r
            (out / f"{n}.vm.json").write_text(json.dumps(res))
            print(n, res["window_s"], file=sys.stderr)


if __name__ == "__main__":
    main()
