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

def main [
    --dir: string = "progbench" # directory holding progbench and the objects
    --iface: string = "eno1np0" # DUT interface under load
    --n: int = 100 # sample rate
    --rounds: int = 2 # passes per GRO setting
    --warmup: string = "3s" # settle time after attach
    --window: string = "15s" # measurement window
    --labels: string = "agent_v3 skip_array_lazy_nowake xdp_skip_array" # space separated
] {
    let out = "/tmp/progbench_offload.jsonl"
    "" | save -f $out
    for gro in [on off] {
        ^ethtool -K $iface gro $gro
        sleep 2sec
        for r in 1..$rounds {
            for l in ($labels | split row " ") {
                let line = (
                    ^$"($dir)/progbench" -obj $"($dir)/($l).o" -label $"($l) gro=($gro)" -attach $iface -n $n -warmup $warmup -window $window
                    | str trim
                )
                $"($line)\n" | save -a $out
                print $"gro=($gro) round ($r) ($l) done"
            }
        }
    }
    ^ethtool -K $iface gro on
    print $"wrote ($out)"
}
