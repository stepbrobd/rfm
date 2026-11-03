#!/usr/bin/env nu

# Per-commit cost and accuracy of the object the agent loads. For each
# revision it takes the committed probe/rfm_bpfel.o, then over --rounds rounds
# in shuffled order (so drift does not favour one revision) times every
# program and frame with progbench test runs, and runs the accuracy harness
# once per revision. Runs as the user from the repository root, progbench
# itself runs under --sudo. Build the binary first with
# go build -o <out>/progbench ./bench/progbench. Writes <out>/tr.jsonl and
# <out>/acc.jsonl, then prints the median and minimum ns per run of each
# revision and their change against the first.

def main [
    ...revs: string # revisions to compare, the first is the baseline
    --out: string = "result-commits" # output directory, holds progbench
    --ns: string = "100 1" # sample rates
    --rounds: int = 3 # shuffled passes over the revisions
    --trials: int = 3 # trials per point and round, each on a fresh load
    --repeat: int = 2000000 # runs per trial (400000 at N=1)
    --cpu: int = 2 # CPU to pin to
    --accuracy: string = "1000:1000" # K:M at N=100, empty to skip
    --sudo: string = "sudo" # privilege wrapper for progbench, empty when root
] {
    mkdir $out
    let bin = $"($out)/progbench" | path expand
    if not ($bin | path exists) {
        error make {
            msg: $"($bin) is missing, build it with go build -o ($bin) ./bench/progbench"
        }
    }
    let objs = $revs | each {|r|
        let sha = ^git rev-parse --short $r | str trim
        let obj = $"($out)/($sha).o"
        ^git show $"($sha):probe/rfm_bpfel.o" | save -f --raw $obj
        {sha: $sha obj: $obj}
    }
    let run = {|args|
        if ($sudo | is-empty) { ^$bin ...$args } else { ^$sudo $bin ...$args }
    }

    let tr = $"($out)/tr.jsonl"
    "" | save -f $tr
    for round in 1..$rounds {
        for o in ($objs | shuffle) {
            for n in ($ns | split row " ") {
                let rep = if $n == "1" { 400000 } else { $repeat }
                do $run [
                    -obj
                    $o.obj
                    -label
                    $o.sha
                    -n
                    $n
                    -repeat
                    $rep
                    -trials
                    $trials
                    -cpu
                    $cpu
                ]
                | lines
                | each {|l| $l | from json | insert round $round | to json -r }
                | str join "\n"
                | $in + "\n"
                | save -a $tr
            }
            print $"round ($round) ($o.sha) done"
        }
    }

    let acc = $"($out)/acc.jsonl"
    "" | save -f $acc
    if not ($accuracy | is-empty) {
        for o in $objs {
            do $run [
                -obj
                $o.obj
                -label
                $o.sha
                -n
                100
                -cpu
                $cpu
                -accuracy
                $accuracy
            ]
            | str trim
            | $in + "\n"
            | save -a $acc
        }
    }

    # median and minimum over every trial of every round, kernel ns for XDP
    # whose wall clock carries the test run loop, wall clock ns otherwise.
    # Load from other processes only adds time, so the minimum tracks the
    # uncontended cost, and passing two revisions with identical objects
    # shows the noise floor of the run
    let rows = open $tr
    | lines
    | where {|l| $l != "" }
    | each {|l| $l | from json }
    | each {|r|
        let xs = if $r.prog == "rfm_xdp" { $r.ns_runs } else { $r.wall_ns_runs }
        {sha: $r.label prog: $r.prog frame: $r.frame n: $r.n xs: $xs}
    }
    | group-by --to-table sha prog frame n
    | each {|g|
        let xs = $g.items.xs | flatten
        {sha: $g.sha prog: $g.prog frame: $g.frame n: $g.n median: ($xs | math median) min: ($xs | math min)}
    }
    let base = $objs.0.sha
    let table = $rows | each {|r|
        let b = $rows | where sha == $base and prog == $r.prog and frame == $r.frame and n == $r.n | first
        {
            sha: $r.sha
            prog: $r.prog
            frame: $r.frame
            n: $r.n
            median: ($r.median | math round --precision 1)
            min: ($r.min | math round --precision 1)
            d_median: ($r.median - $b.median | math round --precision 1)
            d_min: ($r.min - $b.min | math round --precision 1)
        }
    }
    print ($table | sort-by n prog frame sha | to md --pretty)
    if not ($accuracy | is-empty) {
        print (
            open $acc | lines | where {|l| $l != "" } | each {|l| $l | from json }
            | each {|r| {sha: $r.label bias: $r.bias std_over_binomial: ($r.std_rel_err / $r.bernoulli_std | math round --precision 3) coverage: $r.coverage} }
            | table --index false
        )
    }
}
