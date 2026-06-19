#!/usr/bin/env nu

# 2-node real-NIC ingress measurement (DUT side). rfm monitors a real NIC while a
# peer node generates rate-capped UDP. Captures real i40e NAPI/IRQ path cost,
# hardware RSS queue spread, and sampled accuracy for the test flows (src ports
# 10000-10999). Ground truth (sent count) comes from the peer's pktgen.
# Run detached: nohup nu twonode.nu --iface ens3f0np0 --secs 18 --n 100 &

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

# per-RX-queue packet counts -> {queue: packets}
def qrx [iface: string] {
    ^ethtool -S $iface
    | lines
    | parse --regex 'rx-(?<q>\d+)\.packets:\s+(?<p>\d+)'
    | reduce -f {} {|r, acc| $acc | insert $r.q ($r.p | into int) }
}

def main [
  --iface: string = "ens3f0np0"  # real NIC to monitor
  --secs: int = 18               # measurement window
  --n: int = 100                 # sample rate
  --port: int = 4739             # IPFIX collector port
] {
    let clk = (^getconf CLK_TCK | into int)
    bpf-stats true
    let gj = (
        job spawn {|| ^goflow2 -listen $"netflow://:($port)" out> /tmp/goflow.json err> /tmp/goflow.log }
    )
    sleep 1sec
    let toml = $'[agent]
interfaces=["($iface)"]
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
    sleep 2sec

    let q0 = (qrx $iface)
    let st0 = (ingress-stat)
    let m0 = (metrics)
    let rx0 = (metric-sum $m0 "rfm_interface_rx_packets_total")
    let c0 = (proc-cpu $r.pid)
    let t0 = (date now)
    sleep ($secs * 1sec)
    let t1 = (date now)
    let q1 = (qrx $iface)
    let st1 = (ingress-stat)
    let m1 = (metrics)
    let rx1 = (metric-sum $m1 "rfm_interface_rx_packets_total")
    let c1 = (proc-cpu $r.pid)
    let dur = (($t1 - $t0) / 1sec)

    rfm-stop $r.jid
    sleep 1sec
    job kill $gj
    ^pkill -f goflow2 | complete | ignore
    bpf-stats false

    let rt = (
        ($st1.run_time_ns? | default 0 | into int) - ($st0.run_time_ns? | default 0 | into int)
    )
    let rc = (
        ($st1.run_cnt? | default 0 | into int) - ($st0.run_cnt? | default 0 | into int)
    )
    let qd = (
        $q1
        | columns
        | each {|k| {queue: ($k | into int), pkts: (($q1 | get $k) - ($q0 | get $k))}}
        | where pkts > 0
        | sort-by pkts --reverse
    )

    let flows = (open --raw /tmp/goflow.json | str replace --all "}{" "}\n{" | lines
    | where {|l| ($l | str trim | is-not-empty)} | each {|l| $l | from json}
    | where {|f| (($f.src_port? | default 0) >= 10000) and (($f.src_port? | default 0) <= 10999)})
    let test_sampled = (
        if ($flows | is-empty) { 0 } else {
            $flows | get packets | math sum
        }
    )

    let out = {
        iface: $iface
        n: $n
        secs: ($dur | math round --precision 1)
        rx_total_delta: (($rx1 - $rx0) | into int)
        sampled_total: (metric-sum $m1 "rfm_flow_sampled_packets" | into int)
        ring_drops: (metric-val $m1 "rfm_collector_dropped_events_total" | into int)
        kern_ns_per_pkt: (if $rc > 0 { ($rt / $rc | math round --precision 1) } else { 0 })
        kern_run_cnt: $rc
        rfm_cores: (
            if $dur > 0 {
                (($c1 - $c0) / $clk / $dur) | math round --precision 3
            } else { 0 }
        )
        queues_hit: ($qd | length)
        test_flows: ($flows | length)
        test_sampled: $test_sampled
        test_scaled: ($test_sampled * $n)
        top_queues: ($qd | first 10)
    }
    $out | to json | save --force /tmp/twonode.json
    $out
}
