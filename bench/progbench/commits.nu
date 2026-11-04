#!/usr/bin/env nu

# Per-commit cost and accuracy of the object the agent loads. For each
# revision it takes the committed probe/rfm_bpfel.o, then over --rounds rounds
# in shuffled order (so drift does not favour one revision or stage) times
# every program and frame with progbench test runs at each of --stages, and
# runs the accuracy harness once per revision and stage. A stage of more than
# one event times the stage programs, which write that many events per ring
# record. Runs as the user from the repository root, progbench itself runs
# under --sudo. Build the binary first with
# go build -o <out>/progbench ./bench/progbench. Writes <out>/tr.jsonl and
# <out>/acc.jsonl, then prints the median and minimum ns per run of each
# revision and stage and their change against the first revision at the first
# stage.

def main [
    ...revs: string # revisions to compare, the first is the baseline
    --out: string = "result-commits" # output directory, holds progbench
    --ns: string = "100 1" # sample rates
    --stages: string = "1" # events per ring record, the first is the baseline
    --rounds: int = 3 # shuffled passes over the revisions and stages
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
    let ks = $stages | split row " "
    let variants = $objs | each {|o| $ks | each {|k| $o | insert k $k } } | flatten

    let tr = $"($out)/tr.jsonl"
    "" | save -f $tr
    for round in 1..$rounds {
        for v in ($variants | shuffle) {
            for n in ($ns | split row " ") {
                let rep = if $n == "1" { 400000 } else { $repeat }
                do $run [
                    -obj
                    $v.obj
                    -label
                    $v.sha
                    -n
                    $n
                    -stage
                    $v.k
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
            print $"round ($round) ($v.sha) stage ($v.k) done"
        }
    }

    let acc = $"($out)/acc.jsonl"
    "" | save -f $acc
    if not ($accuracy | is-empty) {
        for v in $variants {
            do $run [
                -obj
                $v.obj
                -label
                $v.sha
                -n
                100
                -stage
                $v.k
                -cpu
                $cpu
                -accuracy
                $accuracy
            ]
            | from json
            | insert stage ($v.k | into int)
            | to json -r
            | $in + "\n"
            | save -a $acc
        }
    }

    # median and minimum over every trial of every round, kernel ns for XDP
    # whose wall clock carries the test run loop, wall clock ns otherwise.
    # Load from other processes only adds time, so the minimum tracks the
    # uncontended cost, and passing two revisions with identical objects
    # shows the noise floor of the run. A stage program shows under the name
    # of the program it stages for, with its stage
    let rows = open $tr
    | lines
    | where {|l| $l != "" }
    | each {|l| $l | from json }
    | each {|r|
        let xs = if $r.prog == "rfm_xdp" { $r.ns_runs } else { $r.wall_ns_runs }
        {sha: $r.label stage: ($r.stage? | default 1) prog: ($r.prog | str replace "_staged" "") frame: $r.frame n: $r.n xs: $xs}
    }
    | group-by --to-table sha stage prog frame n
    | each {|g|
        let xs = $g.items.xs | flatten
        {sha: $g.sha stage: ($g.stage | into int) prog: $g.prog frame: $g.frame n: $g.n median: ($xs | math median) min: ($xs | math min)}
    }
    let base = $objs.0.sha
    let base_stage = $ks.0 | into int
    let table = $rows | each {|r|
        # a program the baseline lacks has no change to show
        let b = $rows | where sha == $base and stage == $base_stage and prog == $r.prog and frame == $r.frame and n == $r.n
        {
            sha: $r.sha
            stage: $r.stage
            prog: $r.prog
            frame: $r.frame
            n: $r.n
            median: ($r.median | math round --precision 1)
            min: ($r.min | math round --precision 1)
            d_median: (if ($b | is-empty) { null } else { $r.median - $b.0.median | math round --precision 1 })
            d_min: (if ($b | is-empty) { null } else { $r.min - $b.0.min | math round --precision 1 })
        }
    }
    print ($table | sort-by n prog frame sha stage | to md --pretty)
    if not ($accuracy | is-empty) {
        print (
            open $acc | lines | where {|l| $l != "" } | each {|l| $l | from json }
            | each {|r| {sha: $r.label stage: $r.stage bias: $r.bias std_over_binomial: ($r.std_rel_err / $r.bernoulli_std | math round --precision 3) coverage: $r.coverage} }
            | table --index false
        )
    }
}
