#!/usr/bin/env nu

# DUT-side real-NIC overhead sweep over sample_rate, under a sustained external
# flood (start gen.nu on the peer FIRST). Reports the exact counter rate, ring
# drops, real-NIC kernel ns/pkt, kernel + userspace cores, and cores-per-Mpps
# per N. Default 64 RX queues. Run detached; reads /tmp/realnic.json after.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

def main [
  --iface: string = "ens3f0np0"
  --ns: string = "1 10 100 1024"  # sample rates to sweep
  --secs: int = 15                # measurement window per N
  --warmup: int = 3               # settle time after rfm attach
] {
    let clk = (^getconf CLK_TCK | into int)
    let ns = $ns | split row ' ' | each {|x| $x | into int}
    bpf-stats true
    let rows = ($ns | each {|n|
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
    let st0 = (ingress-stat)
    let m0 = (metrics)
    let rx0 = (metric-sum $m0 "rfm_interface_rx_packets_total")
    let c0 = (proc-cpu $r.pid)
    let t0 = (date now)
    sleep ($secs * 1sec)
    let t1 = (date now)
    let st1 = (ingress-stat)
    let m1 = (metrics)
    let rx1 = (metric-sum $m1 "rfm_interface_rx_packets_total")
    let c1 = (proc-cpu $r.pid)
    let dur = (($t1 - $t0) / 1sec)
    rfm-stop $r.jid
    let rt1 = $st1.run_time_ns? | default 0 | into int
    let rt0 = $st0.run_time_ns? | default 0 | into int
    let rt = $rt1 - $rt0
    let rc1 = $st1.run_cnt? | default 0 | into int
    let rc0 = $st0.run_cnt? | default 0 | into int
    let rc = $rc1 - $rc0
    let drx = $rx1 - $rx0 | into int
    let dc = ($c1 - $c0)
    let pps = if $dur > 0 { ($drx / $dur | math round) } else { 0 }
    let kcores = if $dur > 0 { $rt / 1000000000 / $dur | math round --precision 3 } else { 0 }
    let ucores = if $dur > 0 { $dc / $clk / $dur | math round --precision 3 } else { 0 }
    {
      "N": $n
      "rx pps": $pps
      "ring drops": (metric-val $m1 "rfm_collector_dropped_events_total" | into int)
      "ns/pkt": (if $rc > 0 { ($rt / $rc | math round --precision 1) } else { 0 })
      "kern cores": $kcores
      "user cores": $ucores
      "cores/Mpps": (if $pps > 0 { ($kcores + $ucores) / ($pps / 1000000) | math round --precision 3 } else { 0 })
    }
  })
    bpf-stats false
    $rows | to json | save --force /tmp/realnic.json
    $rows
}
