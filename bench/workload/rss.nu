#!/usr/bin/env nu

# DUT-side hardware-RSS sweep on a real NIC, under a sustained external flood
# (start gen.nu on the peer FIRST, many flows). For each RX-queue count (ethtool
# -L combined) and sample rate, reports how many queues took traffic, the exact
# counter rate, ring drops, and kernel/userspace cores. At fixed offered load,
# N=100 stays flat (no contention) while N=1 makes more producer CPUs contend on
# the one shared ring buffer -- the real-NAPI analogue of the veth crossover.
# Resets the NIC (ethtool -L), so run DETACHED; reads /tmp/rss.json after.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

def qspread [iface: string] {
    ^ethtool -S $iface
    | lines
    | parse --regex 'rx-(?<q>\d+)\.packets:\s+(?<p>\d+)'
    | each {|r| {q: ($r.q | into int), p: ($r.p | into int)}}
}

def main [
  --iface: string = "ens3f0np0"
  --queues: string = "1 2 4 8 16 32 64"  # RX queue counts to sweep
  --ns: string = "100 1"                  # sample rates
  --secs: int = 12                        # window per cell
  --warmup: int = 4                       # settle after rfm attach
] {
    let clk = (^getconf CLK_TCK | into int)
    let queues = $queues | split row ' ' | each {|x| $x | into int}
    let ns = $ns | split row ' ' | each {|x| $x | into int}
    bpf-stats true
    let rows = ($ns | each {|n|
    $queues | each {|q|
      ^ethtool -L $iface combined $q | complete | ignore
      sleep 3sec
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
      let s0 = (qspread $iface)
      let st0 = (ingress-stat)
      let m0 = (metrics)
      let rx0 = (metric-sum $m0 "rfm_interface_rx_packets_total")
      let c0 = (proc-cpu $r.pid)
      let t0 = (date now)
      sleep ($secs * 1sec)
      let t1 = (date now)
      let s1 = (qspread $iface)
      let st1 = (ingress-stat)
      let m1 = (metrics)
      let rx1 = (metric-sum $m1 "rfm_interface_rx_packets_total")
      let c1 = (proc-cpu $r.pid)
      let dur = (($t1 - $t0) / 1sec)
      rfm-stop $r.jid
      let rt1 = $st1.run_time_ns? | default 0 | into int
      let rt0 = $st0.run_time_ns? | default 0 | into int
      let rt = $rt1 - $rt0
      let drx = $rx1 - $rx0 | into int
      let dc = ($c1 - $c0)
      let moved = $s1 | each {|e| (($e.p) - ($s0 | where q == $e.q | get 0?.p? | default 0))} | where {|d| $d > 1000} | length
      {
        "N": $n
        "queues set": $q
        "queues hit": $moved
        "rx pps": (if $dur > 0 { ($drx / $dur | math round) } else { 0 })
        "ring drops": (metric-val $m1 "rfm_collector_dropped_events_total" | into int)
        "kern cores": (if $dur > 0 { $rt / 1000000000 / $dur | math round --precision 3 } else { 0 })
        "user cores": (if $dur > 0 { $dc / $clk / $dur | math round --precision 3 } else { 0 })
      }
    }
  } | flatten)
    ^ethtool -L $iface combined 64 | complete | ignore
    bpf-stats false
    $rows | to json | save --force /tmp/rss.json
    $rows
}
