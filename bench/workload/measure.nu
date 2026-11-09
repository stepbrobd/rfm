#!/usr/bin/env nu

# One monitor, one window, one json line, on the DUT while the peer's traffic
# runs (start gen.nu, dpdk.nu or iperf3 first). The monitor starts alone, warms
# up, then two windows follow:
#
# - the main window with bpf_stats off: system busy cores from /proc/stat, the
#   monitor's process cores and RSS, the NIC's port counters, rfm's ring drops,
#   and with --counts the monitor's own packet and byte counts for accuracy
# - the stat window with bpf_stats on: program runs and ns per run, which the
#   stats clock reads inflate, so cores never come from this window
#
# --agent none measures the same windows with nothing attached, the baseline a
# driver subtracts. The driver picks the order and the rounds and every run
# appends one line to --out. Map memory is the sum of bytes_memlock with the
# monitor running minus the sum before it started.
#
# Accuracy (--counts) needs a short export interval, so netobserv runs with a
# 1 s active timeout there and its default otherwise. hsflowd's sFlow goes to
# sflow_decode.py. The libpcap tools have no counts here.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

const HERE = path self | path dirname

# non-idle jiffies across all CPUs from /proc/stat
def cpu-busy [] {
    let f = (open --raw /proc/stat | lines | where {|l| $l | str starts-with "cpu "} | first
    | split row ' ' | where {|x| $x != ""})
    let v = $f | skip 1 | each {|x| $x | into int}
    let idle = ($v | get 3) + ($v | get 4)
    let total = $v | math sum
    $total - $idle
}

def map-mem [] {
    let xs = ^bpftool map show -j | from json | get bytes_memlock? | compact
    if ($xs | is-empty) {
        0
    } else {
        $xs | math sum
    }
}

def map-ids [] {
    ^bpftool map show -j | from json | get id
}

# the hash maps of 512 entries or more among the given ids, the flow tables, with their entry counts
def flow-tables [ids: list<any>] {
    ^bpftool map show -j
    | from json
    | where {|m| ($m.id in $ids) and ($m.type | str contains "hash") and (($m.max_entries? | default 0) >= 512) }
    | each {|m|
        # jq counts a dump of a million entries in seconds, nu's from json would take minutes
        let d = ^bash -c $"set -o pipefail; bpftool map dump id ($m.id) -j | jq length" | complete
        let entries = if $d.exit_code == 0 { $d.stdout | str trim | into int } else { -1 }
        {name: $m.name, type: $m.type, max_entries: $m.max_entries, memlock_kb: ($m.bytes_memlock / 1024 | math round), entries: $entries}
    }
}

# run_cnt and run_time_ns summed over every loaded program
def prog-stats [] {
    let p = ^bpftool prog show -j | from json
    let cnt = $p | get run_cnt? | compact | append 0 | math sum
    let t = $p | get run_time_ns? | compact | append 0 | math sum
    {cnt: $cnt, t: $t}
}

# the port and driver counters a window compares against
def nic [iface: string] {
    let keep = [
        rx_packets_phy
        tx_packets_phy
        rx_bytes_phy
        tx_bytes_phy
        rx_out_of_buffer
        rx_discards_phy
        tx_discards_phy
        rx_packets
        tx_packets
        rx_bytes
        tx_bytes
    ]
    let r = ^ethtool -S $iface | complete
    if $r.exit_code != 0 {
        error make {msg: $"ethtool -S ($iface) failed: ($r.stderr | str trim)"}
    }
    let kv = $r.stdout | lines | parse --regex '^\s+(?<k>[a-z0-9_]+):\s+(?<v>\d+)$'
    let sel = $kv | where {|x| $x.k in $keep }
    let rec = $sel | reduce --fold {} {|x, acc| $acc | upsert $x.k ($x.v | into int) }
    let sysrx = open --raw $"/sys/class/net/($iface)/statistics/rx_packets" | str trim | into int
    let systx = open --raw $"/sys/class/net/($iface)/statistics/tx_packets" | str trim | into int
    $rec | upsert dev_rx_packets $sysrx | upsert dev_tx_packets $systx
}

def delta [a: record, b: record] {
    $b | columns | reduce --fold {} {|k, acc| $acc | upsert $k (($b | get $k) - ($a | get -o $k | default 0)) }
}

def kill-all [] {
    ^pkill -KILL -x softflowd | complete | ignore
    ^pkill -KILL -x pmacctd | complete | ignore
    ^pkill -KILL -x hsflowd | complete | ignore
    ^pkill -KILL -f '^netobserv-ebpf-agent' | complete | ignore
    ^pkill -KILL -f 'measure-neto.sh' | complete | ignore
    ^pkill -KILL -f '^[^ ]*rfm agent' | complete | ignore
    ^pkill -KILL -f 'sflow_decode.py' | complete | ignore
    null
}

# start a command detached and return its pid
def spawn [cmd: string, log: string] {
    let r = ^bash -c $"setsid nohup ($cmd) > ($log) 2>&1 < /dev/null & echo $!" | complete
    $r.stdout | str trim | into int
}

# the rfm label lines summed per metric and direction or family
def rfm-counts [] {
    let m = metrics
    let rows = $m | lines | parse --regex '^(?<name>rfm_(?:interface_(?:rx|tx)_(?:packets|bytes)|flow_(?:sampled_)?(?:packets|bytes))_total)\{(?<labels>[^}]*)\} (?<v>\S+)$'
    let keyed = $rows | each {|r|
        let d = $r.labels | parse --regex 'direction="(?<d>\w+)"' | get d.0? | default ""
        let f = $r.labels | parse --regex 'family="(?<f>\w+)"' | get f.0? | default ""
        let k = if ($d | is-empty) { $"($r.name).($f)" } else { $"($r.name).($d)" }
        {k: $k, v: ($r.v | into float)}
    }
    $keyed | group-by k | items {|k, xs| {k: $k, v: ($xs | get v | math sum)} } | reduce --fold {} {|x, acc| $acc | upsert $x.k $x.v }
}

# rfm's collector gauges and counters, the user space flow table that bpftool cannot see
def rfm-coll [] {
    metrics
    | lines
    | parse --regex '^rfm_collector_(?<k>\w+) (?<v>\S+)$'
    | reduce --fold {} {|x, acc| $acc | upsert $x.k ($x.v | into float) }
}

def neto-counts [file: string, t0: float, t1: float] {
    if not ($file | path exists) { return {} }
    let recs = open --raw $file | lines | where {|l| $l | str starts-with "{" } | each {|l| $l | from json }
    let inwin = $recs | where {|r| let e = ($r.TimeFlowEndMs? | default 0) / 1000; $e > $t0 and $e <= $t1 }
    let flat = $inwin | each {|r|
        let s = $r.Sampling? | default 1
        let s1 = if $s == 0 { 1 } else { $s }
        let dirs = $r.IfDirections? | default [($r.FlowDirection? | default (-1))] | uniq
        $dirs | each {|d| {d: $d, p: (($r.Packets? | default 0) * $s1), b: (($r.Bytes? | default 0) * $s1), s: $s1} }
    } | flatten
    let by = $flat | group-by d | items {|d, xs| {d: $d, packets: ($xs | get p | math sum), bytes: ($xs | get b | math sum), rates: ($xs | get s | uniq)} }
    {
        records: ($inwin | length)
        by_direction: $by
    }
}

def hsf-counts [file: string, t0: float, t1: float] {
    if not ($file | path exists) { return {} }
    let recs = open --raw $file | lines | each {|l| $l | from json }
    let errs = $recs | where {|r| $r.error? != null } | length
    let inwin = $recs | where {|r| $r.error? == null and $r.t > $t0 and $r.t <= $t1 }
    let by = $inwin | group-by {|r| $"in($r.in)_out($r.out)" } | items {|k, xs| {k: $k, samples: ($xs | length), packets: ($xs | get rate | math sum), bytes: ($xs | each {|r| $r.rate * $r.flen } | math sum), rates: ($xs | get rate | uniq)} }
    {errors: $errs, by_port: $by}
}

def main [
  --agent: string               # none, rfm, netobserv, hsflowd, pmacctd or softflowd
  --iface: string = "ens1f0np0"
  --n: int = 100                # matched sampling rate
  --warmup: int = 10            # seconds from start to the main window
  --secs: int = 45              # main window, bpf_stats off
  --stat-secs: int = 10         # stat window, bpf_stats on, 0 skips it
  --rfm-bpf: string = ""        # extra keys inside rfm's [agent.bpf], newline separated
  --rfm-extra: string = ""      # extra tables appended to rfm's config
  --neto-cache: int = 0         # netobserv CACHE_MAX_FLOWS, 0 keeps its default
  --counts                      # collect the monitor's own counts over the main window
  --tables                      # dump the monitor's flow tables at the end of the main window
  --label: string = ""
  --out: string = "/tmp/measure.jsonl"
] {
    let agents = [
        none
        rfm
        netobserv
        hsflowd
        pmacctd
        softflowd
    ]
    if not ($agent in $agents) {
        error make {msg: $"--agent must be one of ($agents | str join ', ')"}
    }
    kill-all
    bpf-stats false
    sleep 2sec
    let base_mem = map-mem
    let base_ids = map-ids
    let clk = ^getconf CLK_TCK | into int

    # start the monitor, pid 0 for none
    let pid = match $agent {
        none => 0
        "rfm" => {
            # a literal backslash n separates lines, as realnic.nu's --extra does
            let bpf = if ($rfm_bpf | is-empty) { "" } else { $"($rfm_bpf | str replace --all '\n' (char newline))\n" }
            let extra = $rfm_extra | str replace --all '\n' (char newline)
            let toml = $"[agent]\ninterfaces=[\"($iface)\"]\n[agent.bpf]\nsample_rate=($n)\n($bpf)[agent.prometheus]\nhost=\"127.0.0.1\"\nport=9669\n($extra)\n"
            $toml | save --raw --force /tmp/measure-rfm.toml
            let rfm = $env.RFM? | default "rfm"
            let p = spawn $"($rfm) agent -c /tmp/measure-rfm.toml" /tmp/measure-rfm.log
            ^bash -c 'for i in $(seq 1 60); do curl -s --max-time 1 http://127.0.0.1:9669/metrics >/dev/null 2>&1 && exit 0; sleep 0.5; done; exit 1' | complete | ignore
            $p
        }
        "netobserv" => {
            let out = if $counts { "/tmp/measure-neto.jsonl" } else { "/dev/null" }
            ^rm -f /tmp/measure-neto.jsonl
            let fmt = if $counts { ',"stdout":{"format":"json"}' } else { "" }
            let flp = $'{"pipeline":[{"name":"writer","follows":"preset-ingester"}],"parameters":[{"name":"writer","write":{"type":"stdout"($fmt)}}]}'
            let cache = if $neto_cache > 0 { $"export CACHE_MAX_FLOWS=($neto_cache)\n" } else { "" }
            let timeout = if $counts { "export CACHE_ACTIVE_TIMEOUT=1s\n" } else { "" }
            $"#!/usr/bin/env bash\nexport INTERFACES=($iface)\nexport SAMPLING=($n)\nexport EXPORT=direct-flp\n($cache)($timeout)export FLP_CONFIG='($flp)'\nexec netobserv-ebpf-agent > ($out) 2>/tmp/measure-neto.log\n" | save --raw --force /tmp/measure-neto.sh
            ^chmod +x /tmp/measure-neto.sh
            spawn /tmp/measure-neto.sh /dev/null
        }
        "hsflowd" => {
            if $counts {
                ^rm -f /tmp/measure-hsf.jsonl
                spawn $"python3 ($HERE)/sflow_decode.py /tmp/measure-hsf.jsonl" /tmp/measure-sfl.log | ignore
            }
            let mod = which hsflowd | get 0.path | path dirname | path join ".." "lib" "hsflowd" "modules" | path expand
            # hsflowd ignores sampling inside epcap and samples a port that reports a speed at 1 in speed over bps_ratio unless the ratio is 0
            $"sflow {\n  agent = ($iface)\n  sampling = ($n)\n  sampling.bps_ratio = 0\n  collector { ip = 127.0.0.1  udpport = 6343 }\n  epcap { dev = ($iface) }\n}\n" | save --raw --force /tmp/measure-hsflowd.conf
            spawn $"hsflowd -d -f /tmp/measure-hsflowd.conf -l ($mod)" /tmp/measure-hsf.log
        }
        "pmacctd" => {
            $"pcap_interface: ($iface)\naggregate: src_host,dst_host,src_port,dst_port,proto\nplugins: nfprobe\nnfprobe_receiver: 127.0.0.1:9995\nnfprobe_version: 10\nsampling_rate: ($n)\n" | save --raw --force /tmp/measure-pmacctd.conf
            spawn "pmacctd -f /tmp/measure-pmacctd.conf" /tmp/measure-pmd.log
        }
        "softflowd" => {
            spawn $"softflowd -i ($iface) -n 127.0.0.1:9995 -v 10 -s ($n) -d" /tmp/measure-sfd.log
        }
    }
    sleep ($warmup * 1sec)
    if $agent != "none" and not ($"/proc/($pid)" | path exists) {
        error make {msg: $"($agent) exited during warmup, see its log in /tmp"}
    }
    # a label tuple reads 0 in its first scrape, so scrape once before the window
    if $agent == "rfm" {
        metrics | ignore
        sleep 1sec
    }

    # main window, bpf_stats off
    let k0 = if $agent == "rfm" { rfm-coll } else { {} }
    let d0 = if $agent == "rfm" {
        flow-drops | get drops | math sum
    } else {
        0
    }
    # the same order at both ends, so the scrape and the port read share one skew
    let c0 = if $agent == "rfm" and $counts { rfm-counts } else { {} }
    let n0 = nic $iface
    let b0 = cpu-busy
    let p0 = if $pid > 0 { proc-cpu $pid } else { 0 }
    let t0 = (date now | into int) / 1e9
    sleep ($secs * 1sec)
    let t1 = (date now | into int) / 1e9
    let b1 = cpu-busy
    let p1 = if $pid > 0 { proc-cpu $pid } else { 0 }
    let c1 = if $agent == "rfm" and $counts { rfm-counts } else { {} }
    let n1 = nic $iface
    let d1 = if $agent == "rfm" {
        flow-drops | get drops | math sum
    } else {
        0
    }
    let k1 = if $agent == "rfm" { rfm-coll } else { {} }
    let coll = if $agent == "rfm" {
        (delta $k0 $k1) | upsert active_flows ($k1.active_flows? | default 0)
    } else {
        {}
    }
    let rss = if $pid > 0 { proc-rss $pid } else { 0 }
    let mem = (map-mem) - $base_mem
    let tables = if $tables { flow-tables (map-ids | where {|i| not ($i in $base_ids) }) } else { [] }
    let dur = $t1 - $t0
    let sys_cores = ($b1 - $b0) / $clk / $dur | math round --precision 4
    let proc_cores = ($p1 - $p0) / $clk / $dur | math round --precision 4

    # stat window, bpf_stats on
    let st = if $stat_secs > 0 and $agent in [rfm netobserv hsflowd] {
        bpf-stats true
        sleep 1sec
        let s0 = prog-stats
        let m0 = nic $iface
        sleep ($stat_secs * 1sec)
        let s1 = prog-stats
        let m1 = nic $iface
        bpf-stats false
        let runs = $s1.cnt - $s0.cnt
        let ns = if $runs > 0 {
            ($s1.t - $s0.t) / $runs | math round --precision 1
        } else {
            0.0
        }
        let dm = delta $m0 $m1
        {
            runs: $runs
            ns_per_run: $ns
            dev_rx_packets: $dm.dev_rx_packets
            dev_tx_packets: $dm.dev_tx_packets
            secs: $stat_secs
        }
    } else { {} }

    # let the exporters flush the window's last records, then stop
    if $counts { sleep 3sec }
    kill-all
    bpf-stats false

    let own = if not $counts { {} } else {
        match $agent {
            "rfm" => (delta $c0 $c1)
            "netobserv" => (neto-counts /tmp/measure-neto.jsonl $t0 $t1)
            "hsflowd" => (hsf-counts /tmp/measure-hsf.jsonl $t0 $t1)
            _ => { }
        }
    }
    let row = {
        label: $label
        agent: $agent
        n: $n
        host: (sys host | get hostname)
        start: ($t0 | math round)
        secs: ($dur | math round --precision 2)
        sys_cores: $sys_cores
        proc_cores: $proc_cores
        rss_kb: $rss
        map_mem_kb: ($mem / 1024 | math round)
        tables: $tables
        ring_drops: ($d1 - $d0)
        collector: $coll
        nic: (delta $n0 $n1)
        prog: $st
        counts: $own
        rfm_bpf: $rfm_bpf
        rfm_extra: $rfm_extra
        neto_cache: $neto_cache
        gogc: ($env.GOGC? | default "")
    }
    ($row | to json -r) + "\n" | save --append --raw $out
    $row
}
