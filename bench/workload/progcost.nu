#!/usr/bin/env nu

# Per-packet eBPF datapath cost. For each in-kernel agent (rfm, hsflowd epcap,
# netobserv) this reports how often its TC/TCX program runs relative to received
# packets (runs_per_rx) and the average ns spent in the program per run, using
# kernel.bpf_stats_enabled. It complements headtohead.nu (system-wide cores):
# it shows that EVERY agent runs its datapath per-packet (runs_per_rx ~ 1.0), so
# rfm's low cost comes from sampling first and holding no per-flow kernel state,
# not from skipping packets. Run on the DUT under an external flood (gen.nu on
# the peer first). Output is a table and /tmp/progcost.json.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

# sum run_cnt + run_time_ns over all sched_cls (TC/TCX) bpf programs
def prog-stats [] {
    let p = (^bpftool prog show -j | from json | where type == "sched_cls")
    let cnt = (
        $p
        | get run_cnt?
        | compact
        | append 0
        | math sum
    )
    let t = (
        $p
        | get run_time_ns?
        | compact
        | append 0
        | math sum
    )
    let n = $p | length
    {cnt: $cnt, t: $t, n: $n}
}

def rx-pkts [iface: string] {
    open --raw $"/sys/class/net/($iface)/statistics/rx_packets" | str trim | into int
}

# runs_per_rx + avg ns-in-prog over secs while one agent is attached
def prog-cost [iface: string, secs: int] {
    let s0 = (prog-stats)
    let r0 = (rx-pkts $iface)
    sleep ($secs * 1sec)
    let s1 = (prog-stats)
    let r1 = (rx-pkts $iface)
    let dc = $s1.cnt - $s0.cnt
    let dt = $s1.t - $s0.t
    let dr = $r1 - $r0
    let rpr = (
        if $dr > 0 {
            $dc / $dr | math round --precision 2
        } else { 0.0 }
    )
    let ans = (
        if $dc > 0 {
            $dt / $dc | math round --precision 0
        } else { 0 }
    )
    {
        progs: $s1.n
        prog_runs: $dc
        rx_pkts: $dr
        runs_per_rx: $rpr
        avg_ns_in_prog: $ans
    }
}

def main [
  --iface: string = "ens3f0np0"
  --secs: int = 6 # measurement window per agent
  --n: int = 100 # matched sample rate
  --warmup: int = 5 # settle after attach
] {

    # clean slate: a stray/interrupted agent leaves its TC/TCX program attached
    # and running per-packet, which would inflate the next agent's runs_per_rx.
    ^pkill -KILL -f netobserv-ebpf-agent | complete | ignore
    ^pkill -KILL -x hsflowd | complete | ignore
    ^pkill -KILL -f "rfm agent" | complete | ignore
    sleep 1sec

    bpf-stats true

    # rfm
    let toml = $'[agent]
interfaces=["($iface)"]
[agent.bpf]
sample_rate=($n)
[agent.prometheus]
host="127.0.0.1"
port=9669
'
    let r = (rfm-start $toml)
    sleep ($warmup * 1sec)
    let rfmc = (prog-cost $iface $secs)
    rfm-stop $r.jid
    sleep 2sec

    # hsflowd epcap (eBPF/TCX). Binary defaults to /etc/hsflowd/modules, so point
    # -l at the package's own module dir.
    let hsf_mod = (
        which hsflowd
        | get 0.path
        | path dirname
        | path join ".." "lib" "hsflowd" "modules"
        | path expand
    )
    $'sflow {
  agent = ($iface)
  collector { ip = 127.0.0.1  udpport = 6343 }
  epcap { dev = ($iface)  sampling = ($n) }
}
' | save --force /tmp/progcost-hsf.conf
    ^bash -c $"nohup hsflowd -d -f /tmp/progcost-hsf.conf -l ($hsf_mod) >/tmp/progcost-hsf.log 2>&1 &"
    sleep ($warmup * 1sec)
    let hsfc = (prog-cost $iface $secs)
    ^pkill -INT -x hsflowd | complete | ignore
    sleep 2sec

    # netobserv (Sampling=N, direct-flp, no collector). Comm is too long for
    # pgrep -x, so capture the pid (exec keeps the same pid) and kill by pid.
    let flp = '{"pipeline":[{"name":"writer","follows":"preset-ingester"}],"parameters":[{"name":"writer","write":{"type":"stdout"}}]}'
    let neto_sh = $"#!/usr/bin/env bash
export INTERFACES=($iface)
export SAMPLING=($n)
export EXPORT=direct-flp
export FLP_CONFIG='($flp)'
exec netobserv-ebpf-agent
"
    $neto_sh | save --force /tmp/progcost-neto.sh
    ^chmod +x /tmp/progcost-neto.sh
    ^bash -c "nohup /tmp/progcost-neto.sh >/dev/null 2>/tmp/progcost-neto.log & echo $! > /tmp/progcost-neto.pid"
    sleep ($warmup * 1sec)
    let netc = (prog-cost $iface $secs)
    let npid = open /tmp/progcost-neto.pid | str trim | into int
    ^kill -INT $npid | complete | ignore
    sleep 2sec

    bpf-stats false

    let rows = [
        ({agent: $"rfm N=($n)"} | merge $rfmc)
        ({agent: $"hsflowd epcap s=($n)"} | merge $hsfc)
        ({agent: $"netobserv N=($n)"} | merge $netc)
    ]
    $rows | to json | save --force /tmp/progcost.json
    $rows
}
