#!/usr/bin/env nu

# Ring-buffer / wakeup tuning at the worst case (default N=1, where drops occur).

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

def main [
  --n: int = 1                                        # sample rate
  --count: int = 5000000                              # packets per run
  --size: int = 60                                    # packet size
  --rings: string = "262144 1048576 4194304 16777216" # ring_buf_size sweep
  --batches: string = "16 64 256 1024"                # wakeup_batch sweep
] {
    let rings = $rings | split row ' ' | each {|x| $x | into int}
    let batches = $batches | split row ' ' | each {|x| $x | into int}
    let clk = (^getconf CLK_TCK | into int)

    let run = {|ring: int, batch: int|
        let toml = $'[agent]
interfaces=["($env.MON)"]
[agent.bpf]
sample_rate=($n)
ring_buf_size=($ring)
wakeup_batch=($batch)
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
        let mm = (metrics)
        let st = (ingress-stat)
        let rt = (
            if $st == null { 0 } else {
                $st.run_time_ns? | default 0 | into int
            }
        )
        let rc = (
            if $st == null { 0 } else {
                $st.run_cnt? | default 0 | into int
            }
        )
        rfm-stop $r.jid
        let dc = ($c1 - $c0)
        {
            "ring_buf_size": $ring
            "wakeup_batch": $batch
            "ring drops": (metric-val $mm "rfm_collector_dropped_events_total" | into int)
            "sampled": (metric-sum $mm "rfm_flow_sampled_packets" | into int)
            "kernel ns/pkt": (
                if $rc > 0 {
                    ($rt / $rc) | math round --precision 1
                } else { 0 }
            )
            "rfm cores": (
                if $dur > 0 {
                    $dc / $clk / $dur | math round --precision 3
                } else { 0 }
            )
            "gen pps": $pps
        }
    }

    setup-links
    bpf-stats true
    let a = $rings | each {|ring| do $run $ring 64}
    let b = $batches | each {|batch| do $run 262144 $batch}
    bpf-stats false
    teardown-links
    let rows = $a | append $b
    $rows | to json | save --force /tmp/tune.json
    $rows
}
