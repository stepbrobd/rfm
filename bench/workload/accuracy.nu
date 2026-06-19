#!/usr/bin/env nu

# Per-flow sampling accuracy vs exact ground truth.
# K flows x M packets each -> rfm sampled -> IPFIX -> goflow2 -> CSV (for analyze.py).

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

def main [
  --n: int = 100      # sample rate
  --k: int = 1000     # number of flows
  --m: int = 1000     # packets per flow (exact ground truth)
  --port: int = 4739  # IPFIX collector port
  --out: string = ""  # CSV output path
] {
    let out = if ($out | is-empty) { $"/tmp/rfm-accuracy-N($n)-M($m).csv" } else { $out }
    let count = ($k * $m)
    let spmin = 10000
    let spmax = ($spmin + $k - 1)

    setup-links
    let gj = (
        job spawn {|| ^goflow2 -listen $"netflow://:($port)" out> /tmp/goflow.json err> /tmp/goflow.log }
    )
    sleep 1sec
    let toml = $'[agent]
interfaces=["($env.MON)"]
[agent.bpf]
sample_rate=($n)
[agent.collector]
eviction_timeout="1s"
[agent.ipfix]
host="127.0.0.1"
port=($port)
[agent.prometheus]
host="127.0.0.1"
port=9669
'
    let r = (rfm-start $toml)
    pktgen-run $count 60 0 $spmin $spmax | ignore
    sleep 3sec
    rfm-stop $r.jid
    sleep 2sec
    job kill $gj
    ^pkill -f goflow2 | complete | ignore
    teardown-links

    let flows = (open --raw /tmp/goflow.json | str replace --all "}{" "}\n{" | lines | where {|l| ($l | str trim | is-not-empty)}
    | each {|l| $l | from json}
    | where {|f| (($f.proto? | default "") == "UDP") and (($f.src_port? | default 0) >= 10000)}
    | each {|f| {src_port: $f.src_port, ground_truth: $m, sampled: $f.packets, scaled: ($f.packets * $n)}})

    $flows | to csv | save --force $out
    print $"wrote ($out): (($flows | length))/($k) flows, N=($n) M=($m)"
    $flows | first 5
}
