#!/usr/bin/env nu

# Counting accuracy with receive offloads, on the DUT while the peer runs a TCP
# bulk transfer (iperf3 -c <dut> -P 8 -t <long>). For each GRO setting and each
# object, progbench attaches the object and over the window reports the wire
# frames from the mlx5 port counters, the driver count, the object's own exact
# ingress counters and the number of times the ingress program ran, which is
# the number of skbs at TCX or of frames at XDP, the unit an skb counting
# monitor reports. GRO is toggled with ethtool -K, safe only when the NIC
# carries test traffic alone (KaVLAN). Output is one JSON line per GRO setting,
# label and round in /tmp/progbench_offload.jsonl.
#
# --stats runs each label with the kernel's run time statistics on, off or
# both, since they add two clock reads to every run of every loaded program
# and an XDP program runs once per packet where a TCX one runs once per skb
#
# --gro names the GRO settings to run, so that a caller can give each setting
# its own labels in a call of its own, and GRO is back on when the script ends
#
# the label none attaches nothing, as the baseline for busy cores, and the
# order within a round is shuffled so drift in the stream favours no cell

def main [
    --dir: string = "progbench" # directory holding progbench and the objects
    --iface: string = "eno1np0" # DUT interface under load
    --n: int = 100 # sample rate
    --rounds: int = 2 # passes per GRO setting
    --warmup: string = "3s" # settle time after attach
    --window: string = "15s" # measurement window
    --labels: string = "agent_v3 skip_array_lazy_nowake xdp_skip_array" # space separated
    --stats: string = "on" # space separated, on and off
    --gro: string = "on off" # space separated, the GRO settings to run
] {
    let out = "/tmp/progbench_offload.jsonl"
    "" | save -f $out
    # none loads no program to time, so it runs once whatever --stats asks for
    let cells = $labels | split row " " | each {|l|
        let ss = if $l == "none" { ["off"] } else { $stats | split row " " }
        $ss | each {|s| {l: $l, s: $s} }
    } | flatten
    for g in ($gro | split row " ") {
        ^ethtool -K $iface gro $g
        sleep 2sec
        for r in 1..$rounds {
            for c in ($cells | shuffle) {
                let obj = if $c.l == "none" { "none" } else { $"($dir)/($c.l).o" }
                let line = (
                    ^$"($dir)/progbench" -obj $obj -label $"($c.l) gro=($g)" -attach $iface -n $n -warmup $warmup -window $window $"-stats=($c.s == 'on')"
                    | str trim
                )
                $"($line)\n" | save -a $out
                print $"gro=($g) round ($r) ($c.l) stats=($c.s) done"
            }
        }
    }
    ^ethtool -K $iface gro on
    print $"wrote ($out)"
}
