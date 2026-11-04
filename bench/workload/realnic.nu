#!/usr/bin/env nu

# DUT-side real-NIC overhead sweep over sample_rate, under a sustained external
# flood (start gen.nu on the peer FIRST). Reports the exact counter rate, ring
# drops, real-NIC kernel ns/pkt, kernel + userspace cores, and cores-per-Mpps
# per N. N=1 is excluded at line rate (a single userspace consumer cannot drain
# ~14.4M events/s). Run detached; reads /tmp/realnic.json after.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

# rx_out_of_buffer plus rx_discards_phy, the mlx5 drop counters of ethtool -S, a missing one counts as 0
def nic-drops [iface: string] {
    # an external piped on inside a def does not raise on a nonzero exit, complete makes it explicit
    let r = (^ethtool -S $iface | complete)
    if $r.exit_code != 0 {
        error make {
            msg: $"ethtool -S ($iface) failed with exit code ($r.exit_code): ($r.stderr | str trim)"
        }
    }
    $r.stdout
    | lines
    | parse --regex '^\s*(?:rx_out_of_buffer|rx_discards_phy):\s+(?<v>\d+)'
    | get v
    | each {|v| $v | into int }
    | append 0
    | math sum
}

# legacy clsact filters run after the tcx programs, which leaves rfm every packet and the stack none
def drop-on [iface: string] {
    ^tc qdisc add dev $iface clsact
    ^tc filter add dev $iface ingress matchall action drop
}

# fails when the clsact drop is still on iface, since it keeps every packet from the stack
def drop-off [iface: string] {
    ^tc qdisc del dev $iface clsact | complete | ignore
    let r = (^tc qdisc show dev $iface | complete)
    if $r.exit_code != 0 {
        error make {
            msg: $"tc qdisc show dev ($iface) failed, the clsact drop may still be on: ($r.stderr | str trim)"
        }
    }
    if ($r.stdout | str contains "qdisc clsact") {
        error make {
            msg: $"the clsact drop is still on ($iface), remove it with tc qdisc del dev ($iface) clsact"
        }
    }
}

def main [
  --iface: string = "ens3f0np0"
  --ns: string = "10 100 1000"  # sample rates to sweep (base-10; N=1 excluded at line rate)
  --secs: int = 15                # measurement window per N
  --warmup: int = 3               # settle time after rfm attach
  --extra: string = ""            # toml appended to the agent config after [agent.prometheus], \n between lines, such as "[agent.collector]\nmax_flows=2097152"
  --drop                          # drop every ingress packet in a clsact filter after the tcx programs while each agent runs
] {
    let clk = (^getconf CLK_TCK | into int)
    let ns = $ns | split row ' ' | each {|x| $x | into int}
    let extra = $extra | str replace --all '\n' (char newline)
    # a stray agent, or a drop filter left by a killed --drop run, would skew every row
    ^pkill -KILL -f "rfm agent" | complete | ignore
    ^tc qdisc del dev $iface clsact | complete | ignore
    sleep 1sec
    bpf-stats true
    let rows = try {
        $ns | each {|n|
        let toml = $'[agent]
interfaces=["($iface)"]
[agent.bpf]
sample_rate=($n)
[agent.prometheus]
host="127.0.0.1"
port=9669
($extra)
'
        let r = (rfm-start $toml)
        if $drop { drop-on $iface }
        sleep ($warmup * 1sec)
        # drop and nic counters are read first at both ends, which keeps the program and cpu reads next to t0 and t1
        let d0 = flow-drops | get drops | math sum
        let n0 = (nic-drops $iface)
        let st0 = (ingress-stat)
        let c0 = (proc-cpu $r.pid)
        let s0 = (proc-sys $r.pid)
        let t0 = (date now)
        sleep ($secs * 1sec)
        let d1 = flow-drops | get drops | math sum
        let n1 = (nic-drops $iface)
        let t1 = (date now)
        let st1 = (ingress-stat)
        let m1 = (metrics)
        let c1 = (proc-cpu $r.pid)
        let s1 = (proc-sys $r.pid)
        let rss = (proc-rss $r.pid)
        let dur = (($t1 - $t0) / 1sec)
        rfm-stop $r.jid
        if $drop { drop-off $iface }
        let rt1 = $st1.run_time_ns? | default 0 | into int
        let rt0 = $st0.run_time_ns? | default 0 | into int
        let rt = $rt1 - $rt0
        let rc1 = $st1.run_cnt? | default 0 | into int
        let rc0 = $st0.run_cnt? | default 0 | into int
        let rc = $rc1 - $rc0
        let dc = ($c1 - $c0)
        let ds = $s1 - $s0
        let dd = $d1 - $d0
        let dn = $n1 - $n0
        # rx rate from the TC program run_cnt (exact packets rfm processed, via
        # bpftool) -- avoids scraping rfm's HTTP endpoint, which is unreachable under
        # full line-rate saturation
        let pps = if $dur > 0 { ($rc / $dur | math round) } else { 0 }
        let kcores = if $dur > 0 { $rt / 1000000000 / $dur | math round --precision 3 } else { 0 }
        # user cores stays utime+stime as in earlier runs, sys cores is its stime part
        let ucores = if $dur > 0 { $dc / $clk / $dur | math round --precision 3 } else { 0 }
        let scores = if $dur > 0 { $ds / $clk / $dur | math round --precision 3 } else { 0 }
        let nicps = if $dur > 0 { $dn / $dur | math round } else { 0 }
        let rss_mb = $rss / 1024 | math round --precision 1
        let flows = if ($m1 | is-empty) { -1 } else { metric-val $m1 "rfm_collector_active_flows" | into int }
        let evict = if ($m1 | is-empty) { -1 } else { metric-val $m1 "rfm_collector_forced_evictions_total" | into int }
        {
          "N": $n
          "rx pps": $pps
          "ring drops": (if ($m1 | is-empty) { -1 } else { metric-val $m1 "rfm_collector_dropped_events_total" | into int })
          "ns/pkt": (if $rc > 0 { ($rt / $rc | math round --precision 1) } else { 0 })
          "kern cores": $kcores
          "user cores": $ucores
          "cores/Mpps": (if $pps > 0 { ($kcores + $ucores) / ($pps / 1000000) | math round --precision 3 } else { 0 })
          "window drops": $dd
          "drops at start": $d0
          "sys cores": $scores
          "rss MB": $rss_mb
          "active flows": $flows
          "forced evictions": $evict
          "nic drops/s": $nicps
        }
      }
    } finally {
        # a failed step leaves the agent, the drop and bpf stats on, a full sweep leaves only the stats
        ^pkill -f "rfm agent" | complete | ignore
        bpf-stats false
        if $drop { drop-off $iface }
    }
    $rows | to json | save --force /tmp/realnic.json
    $rows
}
