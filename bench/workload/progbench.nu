#!/usr/bin/env nu

# Per-program cost of rfm's TC programs and of its ablation variants, timed
# with BPF_PROG_TEST_RUN by the progbench binary on crafted frames (IPv4,
# IPv6, VLAN and a GRO merged IPv4 TCP skb). No traffic and no NIC involved:
# the kernel runs each program `repeat` times on one pinned CPU and reports
# ns per run. Build the binary and the objects on the dev box first
# (bench/progbench/build.nu), copy both next to this script, run as root.
# Output is one JSON line per label, program, frame and N in /tmp/progbench.jsonl.

def main [
    --dir: string = "progbench" # directory holding progbench and the objects
    --ns: string = "100 1000 1" # sample rates to sweep
    --repeat: int = 2000000 # runs per trial
    --trials: int = 7 # trials per point, each on a fresh load
    --cpu: int = 2 # CPU to pin to
    --labels: string = "" # space separated subset of variants.json, all when empty
] {
    let out = "/tmp/progbench.jsonl"
    "" | save -f $out
    let all = (open $"($dir)/variants.json")
    let labels = if ($labels | is-empty) {
        $all
    } else {
        $labels | split row " "
    }
    for n in ($ns | split row " ") {
        for l in $labels {
            # N=1 emits every run, so fewer runs keep the ring from filling
            let rep = if $n == "1" { 400000 } else { $repeat }
            let lines = (
                ^$"($dir)/progbench" -obj $"($dir)/($l).o" -label $l -n $n -repeat $rep -trials $trials -cpu $cpu
                | lines
            )
            $lines | str join "\n" | $in + "\n" | save -a $out
            print $"($l) N=($n) done"
        }
    }
    print $"wrote ($out)"
}
