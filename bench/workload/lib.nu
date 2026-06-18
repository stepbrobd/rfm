# veth and pktgen helper functions
# use lib.nu *

export-env {
  $env.PG = "/proc/net/pktgen"
  $env.GEN = ($env.GEN? | default "veth0")
  $env.MON = ($env.MON? | default "veth1")
  $env.NET = ($env.NET? | default "10.0.0")
  $env.RFM = ($env.RFM? | default "rfm")
}

# write one command line to a procfs control file
export def pg [file: string, val: string] {
    $"($val)\n" | save --raw --force $file
}

export def setup-links [] {
    ^ip link del $env.GEN | complete | ignore
    ^ip link add $env.GEN type veth peer name $env.MON
    ^ip addr add $"($env.NET).1/24" dev $env.GEN
    ^ip addr add $"($env.NET).2/24" dev $env.MON
    ^ip link set $env.GEN up
    ^ip link set $env.MON up
    [$env.GEN $env.MON] | each {|d| ^ethtool -K $d gro off gso off tso off lro off rx off tx off | complete | ignore }
    null
}

export def teardown-links [] {
    ^ip link del $env.GEN | complete | ignore
    null
}

export def mon-mac [] {
    open --raw $"/sys/class/net/($env.MON)/address" | str trim
}

# utime+stime of a pid in clock ticks
export def proc-cpu [pid: int] {
    let s = open --raw $"/proc/($pid)/stat" | str trim | split row ' '
    (($s | get 13 | into int) + ($s | get 14 | into int))
}

export def bpf-stats [on: bool] {
    ^sysctl -w $"kernel.bpf_stats_enabled=(if $on { 1 } else { 0 })" | complete | ignore
    null
}

# start rfm from a config string
# returns {jid, pid}
export def rfm-start [toml: string] {
    $toml | save --raw --force /tmp/rfm.toml
    let jid = job spawn {|| ^($env.RFM) agent -c /tmp/rfm.toml out+err> /tmp/rfm.log }
    sleep 2sec
    {
        jid: $jid
        pid: (
            ^pgrep -f "rfm agent"
            | lines
            | get 0?
            | default "0"
            | str trim
            | into int
        )
    }
}

export def rfm-stop [jid: int] {
    job kill $jid
    ^pkill -f "rfm agent" | complete | ignore
    sleep 500ms
    null
}

export def metrics [] { ^curl -s http://127.0.0.1:9669/metrics }

# sum the values of every metric line whose name starts with the prefix
export def metric-sum [m: string, prefix: string] {
    $m | lines | where {|l| $l | str starts-with $prefix} | each {|l| $l | split row ' ' | last | into float} | math sum
}

export def metric-val [m: string, prefix: string] {
    let r = $m | lines | where {|l| $l | str starts-with $prefix}
    if ($r | is-empty) { 0.0 } else {
        $r | first | split row ' ' | last | into float
    }
}

# total run_time_ns (ns) across attached rfm TC programs (needs bpf-stats on)
export def kern-ns [] {
    ^bpftool prog show -j
    | from json
    | where {|p| ($p.name? | default "") | str starts-with "rfm_tc"}
    | each {|p| if ($p == null) { 0 } else { $p.run_time_ns? | default 0 | into int }}
    | math sum
}

export def ingress-stat [] {
    ^bpftool prog show -j | from json | where {|p| ($p.name? | default "") == "rfm_tc_ingress"} | get 0?
}

# configure + start one pktgen device on thread 0; returns achieved pps
export def pktgen-run [
    count: int
    size: int
    clone: int
    spmin?: int
    spmax?: int
] {
    ^modprobe pktgen
    pg $"($env.PG)/kpktgend_0" "rem_device_all"
    pg $"($env.PG)/kpktgend_0" $"add_device ($env.GEN)"
    let dev = $"($env.PG)/($env.GEN)"
    pg $dev $"count ($count)"
    pg $dev $"clone_skb ($clone)"
    pg $dev $"pkt_size ($size)"
    pg $dev "delay 0"
    pg $dev $"dst ($env.NET).2"
    pg $dev $"dst_mac (mon-mac)"
    pg $dev "udp_dst_min 9"
    pg $dev "udp_dst_max 9"
    if $spmin != null {
        pg $dev $"udp_src_min ($spmin)"
        pg $dev $"udp_src_max ($spmax)"
    }
    pg $"($env.PG)/pgctrl" "start"
    open --raw $dev
    | lines
    | where {|l| $l =~ 'pps'}
    | get 0?
    | default ""
    | parse --regex '(?<p>\d+)pps'
    | get p.0?
    | default "0"
    | into int
}
