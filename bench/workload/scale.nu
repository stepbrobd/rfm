#!/usr/bin/env nu

# rfm multi-core scaling. C veth pairs, one CPU-pinned pktgen thread each,
# rfm monitors all peers through one shared ring buffer + one consumer.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

def main [
  --cores: string = "1 2 4 8 16 32"  # core counts to sweep
  --n: int = 100                  # sample rate
  --count: int = 2000000          # packets per core
  --size: int = 60                # packet size
  --ring: int = 1048576           # ring_buf_size
] {
    let cores = $cores | split row ' ' | each {|x| $x | into int}
    let clk = (^getconf CLK_TCK | into int)
    ^modprobe pktgen
    bpf-stats true
    let rows = ($cores | each {|c|
    0..63 | each {|i| ^ip link del $"g($i)" | complete | ignore }
    0..($c - 1) | each {|i|
      ^ip link add $"g($i)" type veth peer name $"m($i)"
      ^ip addr add $"10.($i).0.1/24" dev $"g($i)"
      ^ip addr add $"10.($i).0.2/24" dev $"m($i)"
      ^ip link set $"g($i)" up
      ^ip link set $"m($i)" up
      [$"g($i)" $"m($i)"] | each {|d| ^ethtool -K $d gro off gso off tso off lro off rx off tx off | complete | ignore }
    }
    let toml = $'[agent]
interfaces=["m[0-9]+"]
[agent.bpf]
sample_rate=($n)
ring_buf_size=($ring)
[agent.prometheus]
host="127.0.0.1"
port=9669
'
    let r = (rfm-start $toml)
    sleep 1sec
    0..($c - 1) | each {|i|
      pg $"($env.PG)/kpktgend_($i)" "rem_device_all"
      pg $"($env.PG)/kpktgend_($i)" $"add_device g($i)"
      let dev = $"($env.PG)/g($i)"
      pg $dev $"count ($count)"
      pg $dev "clone_skb 0"
      pg $dev $"pkt_size ($size)"
      pg $dev "delay 0"
      pg $dev $"dst 10.($i).0.2"
      pg $dev $"dst_mac (open --raw $'/sys/class/net/m($i)/address' | str trim)"
    }
    let c0 = (proc-cpu $r.pid)
    let k0 = (kern-ns)
    let t0 = (date now)
    pg $"($env.PG)/pgctrl" "start"
    sleep 2sec
    let k1 = (kern-ns)
    let c1 = (proc-cpu $r.pid)
    let dur = (((date now) - $t0) / 1sec)
    let m = (metrics)
    let agg = ($count * $c)
    let pps = (0..($c - 1) | each {|i|
      open --raw $"($env.PG)/g($i)" | lines | where {|l| $l =~ 'pps'} | get 0? | default ""
        | parse --regex '(?<p>\d+)pps' | get p.0? | default "0" | into int
    } | math sum)
    let rx = (metric-sum $m "rfm_interface_rx_packets_total")
    rfm-stop $r.jid
    let dk = ($k1 - $k0)
    let dc = ($c1 - $c0)
    {
      "cores": $c
      "agg sent": $agg
      "rx (exact)": ($rx | into int)
      "exact %": ($rx / $agg * 100 | math round --precision 2)
      "sampled": (metric-sum $m "rfm_flow_sampled_packets" | into int)
      "ring drops": (metric-val $m "rfm_collector_dropped_events_total" | into int)
      "kernel cores": (if $dur > 0 { $dk / 1000000000 / $dur | math round --precision 3 } else { 0 })
      "rfm cores": (if $dur > 0 { $dc / $clk / $dur | math round --precision 3 } else { 0 })
      "agg pps": $pps
    }
  })
    bpf-stats false
    0..63 | each {|i| ^ip link del $"g($i)" | complete | ignore }
    $rows | to json | save --force /tmp/scale.json
    $rows
}
