#!/usr/bin/env nu

# Per-packet cost of rfm's TC programs and ablation variants on a real NIC.
# Each object is attached with TCX (ingress at the head, egress at the tail,
# like the agent), or with native XDP on ingress when it has an rfm_xdp
# program, a goroutine drains the ring like a consumer, and over a fixed
# window the binary reads bpf_stats run time per run, system busy and softirq
# cores from /proc/stat, the interface's rx pps, the mlx5 port counters and
# the object's own exact ingress counters. Run on the DUT as root while the
# peer floods (gen.nu or dpdk.nu). "none" measures the interface with nothing
# attached, as the baseline for busy cores. The order is shuffled
# per round so drift in the offered load does not favour one variant.
# Output is one JSON line per label and round in --out.

def main [
    --dir: string = "progbench" # directory holding progbench and the objects
    --iface: string = "eno1np0" # DUT interface under load
    --n: int = 100 # sample rate
    --rounds: int = 3 # passes over the label list
    --warmup: string = "5s" # settle time after attach
    --window: string = "20s" # measurement window
    --labels: string = "none empty agent_v1 agent_v3 thresh_array skip_array thresh_array_lazy_nowake skip_array_lazy_nowake nocounter_thresh sampled_thresh sampled_skip xdp_empty xdp_skip_array" # space separated
    --out: string = "/tmp/progbench_insitu.jsonl" # JSON lines output
] {
    "" | save -f $out
    let ls = $labels | split row " "
    for r in 1..$rounds {
        for l in ($ls | shuffle) {
            let obj = if $l == "none" { "none" } else { $"($dir)/($l).o" }
            let line = (
                ^$"($dir)/progbench" -obj $obj -label $l -attach $iface -n $n -warmup $warmup -window $window
                | str trim
            )
            $"($line)\n" | save -a $out
            print $"round ($r) ($l) done"
        }
    }
    print $"wrote ($out)"
}
