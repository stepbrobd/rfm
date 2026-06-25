#!/usr/bin/env nu

# rfm datapath overhead vs sample_rate (single flow, single node).

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

def main [
  --rates: string = "1 10 100 1000"  # sample rates to sweep (base-10)
  --count: int = 5000000             # packets per run
  --size: int = 60                   # packet size
] {
    let rates = $rates | split row ' ' | each {|x| $x | into int}
    let clk = (^getconf CLK_TCK | into int)
    setup-links
    bpf-stats true
    let rows = ($rates | each {|n|
    let toml = $'[agent]
interfaces=["($env.MON)"]
[agent.bpf]
sample_rate=($n)
[agent.prometheus]
host="127.0.0.1"
port=9669
'
    let r = (rfm-start $toml)
    let c0 = (proc-cpu $r.pid)
    let t0 = (date now)
    let pps = (pktgen-run $count $size 0)
    sleep 2sec
    let c1 = (proc-cpu $r.pid)
    let dur = (((date now) - $t0) / 1sec)
    let m = (metrics)
    let rx = (metric-sum $m "rfm_interface_rx_packets_total")
    let st = (ingress-stat)
    let rt = if ($st == null) { 0 } else { $st.run_time_ns? | default 0 | into int }
    let rc = if ($st == null) { 0 } else { $st.run_cnt? | default 0 | into int }
    rfm-stop $r.jid
    let dc = ($c1 - $c0)
    {
      "sample rate": $n
      "sent": $count
      "rx (exact)": ($rx | into int)
      "exact %": ($rx / $count * 100 | math round --precision 3)
      "sampled": (metric-sum $m "rfm_flow_sampled_packets" | into int)
      "ring drops": (metric-val $m "rfm_collector_dropped_events_total" | into int)
      "kernel ns/pkt": (if $rc > 0 { ($rt / $rc) | math round --precision 1 } else { 0 })
      "rfm cores": (if $dur > 0 { $dc / $clk / $dur | math round --precision 3 } else { 0 })
      "gen pps": $pps
    }
  })
    bpf-stats false
    teardown-links
    $rows | to json | save --force /tmp/overhead.json
    $rows
}
