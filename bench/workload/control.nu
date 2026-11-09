#!/usr/bin/env nu

# rfm's control surface under load, on the DUT while the peer's traffic runs
# (start gen.nu first). One json line per part goes to --out:
#
# - set: --changes calls of rfm set sample-rate cycling 10, 100 and 1000. Each
#   records the command's wall time, the time until rfm_bpf_sample_rate shows
#   the new rate, and after --settle the sampled packet rate against the exact
#   one, which should be 1 in the new rate.
# - continuity: across the whole set part, the exact counters against the
#   port counters, and the flow estimate against the exact counters, which a
#   rate change must not break.
# - restart: the agent stopped and started again with pinned counters. The
#   counters must continue from their values, not from zero, and the packets
#   they miss are those of the time without programs attached.
# - timeline: with --timeline, one sample a second for --secs of the applied
#   rate, sampled and exact rates and ring drops, for adaptive sampling while
#   the driver ramps the generator. --adaptive turns it on, up to 1000.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

const SOCK = "/tmp/rfm-bench.sock"
const PIN = "/sys/fs/bpf/rfm-bench"

def rx-phy [iface: string] {
    ^ethtool -S $iface | lines | parse --regex '^\s+rx_packets_phy:\s+(?<v>\d+)$' | get v.0 | into int
}

# exact received packets over the ip families, the flow estimate and the samples of ingress
def counts [] {
    let m = metrics
    let rows = $m | lines | parse --regex '^(?<name>rfm_(?:interface_rx_packets|flow_packets|flow_sampled_packets)_total)\{(?<labels>[^}]*)\} (?<v>\S+)$'
    let ex = $rows | where {|r| $r.name == "rfm_interface_rx_packets_total" and not ($r.labels | str contains 'family="other"') } | get v | each {|v| $v | into float } | append 0 | math sum
    let ing = $rows | where {|r| $r.labels | str contains 'direction="ingress"' }
    let est = $ing | where name == "rfm_flow_packets_total" | get v | each {|v| $v | into float } | append 0 | math sum
    let smp = $ing | where name == "rfm_flow_sampled_packets_total" | get v | each {|v| $v | into float } | append 0 | math sum
    let rate = $m | lines | parse --regex '^rfm_bpf_sample_rate (?<v>\S+)$' | get v.0? | default "0" | into float
    {
        exact: $ex
        est: $est
        samples: $smp
        rate: $rate
    }
}

def drops [] {
    flow-drops | get drops | math sum
}

def start [toml: string] {
    $toml | save --raw --force /tmp/control-rfm.toml
    let rfm = $env.RFM? | default "rfm"
    let r = ^bash -c $"setsid nohup ($rfm) agent -c /tmp/control-rfm.toml > /tmp/control-rfm.log 2>&1 < /dev/null & echo $!" | complete
    ^bash -c 'for i in $(seq 1 60); do curl -s --max-time 1 http://127.0.0.1:9669/metrics >/dev/null 2>&1 && exit 0; sleep 0.5; done; exit 1' | complete | ignore
    $r.stdout | str trim | into int
}

def stop [pid: int] {
    ^kill -TERM $pid | complete | ignore
    for i in 1..40 {
        if not ($"/proc/($pid)" | path exists) { break }
        sleep 250ms
    }
    ^pkill -KILL -f '^[^ ]*rfm agent' | complete | ignore
}

def main [
  --iface: string = "ens1f0np0"
  --n: int = 100                  # starting sample rate
  --bpf: string = ""              # toml lines appended under [agent.bpf], \n between lines
  --changes: int = 12             # rfm set calls in the set part
  --settle: int = 3               # seconds after a change before its rate is read
  --window: int = 3               # seconds of each rate reading
  --down: int = 5                 # seconds the agent stays stopped in the restart part
  --timeline                      # sample a timeline only, for adaptive against static sampling
  --adaptive                      # adaptive sampling on, up to a rate of 1000
  --secs: int = 120               # timeline length
  --label: string = ""
  --out: string = "/tmp/control.jsonl"
] {
    ^pkill -KILL -f '^[^ ]*rfm agent' | complete | ignore
    ^rm -rf $PIN
    bpf-stats false
    sleep 1sec
    let bpf = if ($bpf | is-empty) { "" } else { $"($bpf | str replace --all '\n' (char newline))\n" }
    let ad = if $adaptive { "adaptive_sampling=true\nmax_sample_rate=1000\n" } else { "" }
    let toml = $"[agent]\ninterfaces=[\"($iface)\"]\n[agent.bpf]\nsample_rate=($n)\npin_path=\"($PIN)\"\n($ad)($bpf)[agent.prometheus]\nhost=\"127.0.0.1\"\nport=9669\n[agent.control]\nsocket=\"($SOCK)\"\n"
    let rfm = $env.RFM? | default "rfm"
    let host = ^hostname | str trim
    mut pid = start $toml
    sleep 5sec

    if $timeline {
        let rows = (1..$secs | each {|i|
            let a = counts
            let p = rx-phy $iface
            let d = drops
            sleep 1sec
            let b = counts
            let q = rx-phy $iface
            let e = drops
            {t: $i, ts: ((date now | into int) / 1e9), rate: $b.rate, wire_pps: ($q - $p), exact_pps: ($b.exact - $a.exact), sampled_pps: ($b.samples - $a.samples), est_pps: ($b.est - $a.est), drops: ($e - $d)}
        })
        {
            label: $label
            part: "timeline"
            host: $host
            adaptive: $adaptive
            n: $n
            bpf: $bpf
            rows: $rows
        } | to json --raw | save --append $out
        "\n" | save --append $out
        stop $pid
        ^rm -rf $PIN
        return
    }

    # set
    let c0 = counts
    let p0 = rx-phy $iface
    let d0 = drops
    let rates = [10 100 1000]
    let sets = (0..($changes - 1) | each {|i|
        let r = $rates | get ($i mod 3)
        let t0 = date now
        let res = ^$rfm set sample-rate $r --socket $SOCK --json | complete
        let t1 = date now
        mut k = 0
        while $k < 200 {
            if (counts | get rate) == ($r | into float) { break }
            sleep 10ms
            $k = $k + 1
        }
        let t2 = date now
        sleep ($settle * 1sec)
        let a = counts
        sleep ($window * 1sec)
        let b = counts
        let ex = $b.exact - $a.exact
        let sm = $b.samples - $a.samples
        {
            rate: $r, exit: $res.exit_code, reply: ($res.stdout | str trim),
            cli_ms: ((($t1 - $t0) | into int) / 1e6), visible_ms: ((($t2 - $t0) | into int) / 1e6),
            exact: $ex, samples: $sm, applied: (if $sm > 0 { $ex / $sm } else { 0 }), est_over_exact: (if $ex > 0 { ($b.est - $a.est) / $ex } else { 0 })
        }
    })
    let c1 = counts
    let p1 = rx-phy $iface
    let d1 = drops
    {
        label: $label
        part: "set"
        host: $host
        n: $n
        bpf: $bpf
        sets: $sets
    } | to json --raw | save --append $out
    "\n" | save --append $out
    {
        label: $label
        part: "continuity"
        host: $host
        wire: ($p1 - $p0)
        exact: ($c1.exact - $c0.exact)
        est: ($c1.est - $c0.est)
        samples: ($c1.samples - $c0.samples)
        drops: ($d1 - $d0)
        exact_over_wire: (($c1.exact - $c0.exact) / ($p1 - $p0))
        est_over_exact: (($c1.est - $c0.est) / ($c1.exact - $c0.exact))
    } | to json --raw | save --append $out
    "\n" | save --append $out

    # restart with the pinned counters
    let r0 = counts
    let q0 = rx-phy $iface
    let t0 = date now
    stop $pid
    let t1 = date now
    sleep ($down * 1sec)
    let t2 = date now
    $pid = start $toml
    let t3 = date now
    let r1 = counts
    let q1 = rx-phy $iface
    sleep 5sec
    let r2 = counts
    let q2 = rx-phy $iface
    {
        label: $label
        part: "restart"
        host: $host
        exact_before: $r0.exact
        exact_after: $r1.exact
        reset: ($r1.exact < $r0.exact)
        wire_gap: ($q1 - $q0)
        exact_gap: ($r1.exact - $r0.exact)
        missed: (($q1 - $q0) - ($r1.exact - $r0.exact))
        stop_s: ((($t1 - $t0) | into int) / 1e9)
        down_s: ((($t3 - $t1) | into int) / 1e9)
        exact_over_wire_after: (($r2.exact - $r1.exact) / ($q2 - $q1))
        rate_after: $r2.rate
    } | to json --raw | save --append $out
    "\n" | save --append $out
    stop $pid
    ^rm -rf $PIN
}
