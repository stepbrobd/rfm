#!/usr/bin/env nu

# Estimation error of the sampling draws, against exact per-flow ground truth,
# without traffic: progbench feeds the ingress program K flows of exactly M
# packets each, one BPF_PROG_TEST_RUN per packet with the flows interleaved
# round robin, then reads every event from the ring and scales each flow's
# samples by N. The threshold and modulo draws are Bernoulli and should match
# the binomial standard deviation sqrt((N-1)/M), the skip count is checked
# against them. --order burst sends each flow back to back instead. Output is
# one JSON line per label, N and M in /tmp/progbench_accuracy_<order>.jsonl.

def main [
    --dir: string = "progbench" # directory holding progbench and the objects
    --flows: int = 1000 # K
    --cpu: int = 2 # CPU to pin to
    --labels: string = "agent_v3 thresh_array skip_array sampled_thresh sampled_skip" # space separated
    --order: string = "round_robin" # round_robin or burst
] {
    let out = $"/tmp/progbench_accuracy_($order).jsonl"
    "" | save -f $out
    # N and M pairs giving M/N of 10 and 100 at the paper's and the fleet's rates
    let points = [[n, m]; [100, 1000] [100, 10000] [10, 100] [10, 1000]]
    for p in $points {
        for l in ($labels | split row " ") {
            let line = (
                ^$"($dir)/progbench" -obj $"($dir)/($l).o" -label $l -n $p.n -cpu $cpu -accuracy (
                    if $order == "burst" { $"($flows):($p.m):burst" } else { $"($flows):($p.m)" }
                )
                | str trim
            )
            $"($line)\n" | save -a $out
            print $"($l) N=($p.n) M=($p.m) ($order) done"
        }
    }
    print $"wrote ($out)"
}
