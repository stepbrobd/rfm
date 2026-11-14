#!/usr/bin/env nu

# A kernel profile by function of one progbench window, on the DUT under load.
# progbench attaches the object and holds it for the window, and bpftrace
# samples the instruction pointer of every CPU for part of that window. The
# files of --out hold the line of progbench (.json), the samples per kernel
# function and per command in user mode (.txt) and the programs on the
# interface before and after the samples (.net), which shows that the object
# stayed attached for all of them. A sample is one CPU for 1/hz of a second, so
# samples over hz and seconds are cores. A key of the kernel map is one address
# printed as its function, so a function has one line per address sampled in
# it and a reader sums them. The sampler costs CPU and wakes the idle CPUs, so
# the busy cores of the line are no measure of cost.
#
# The kernel throttles a sampling event that takes more than
# perf_event_max_sample_rate over HZ samples between two scheduler ticks of its
# CPU, and an idle CPU has no tick, so at the default limits most samples of an
# idle CPU are lost. The limit is lifted for the profile and put back after it,
# and the run fails unless the samples add up to hz times CPUs times seconds.

# the programs attached to the interface at tcx and xdp
def attached [iface: string] {
    let j = ^bpftool -j net show dev $iface | from json | first
    ($j | get -o xdp | default []) ++ ($j | get -o tc | default [])
}

def main [
    --dir: string = "progbench" # directory holding progbench and the objects
    --iface: string = "eno1np0" # DUT interface under load
    --label: string = "none" # object to attach, none attaches nothing
    --n: int = 1000 # sample rate
    --secs: int = 15 # length of the profile
    --hz: int = 499 # samples per second and CPU
    --out: string = "/tmp/kprofile" # prefix of the result files
    --keys: int = 131072 # addresses the kernel map of bpftrace holds
] {
    let obj = if $label == "none" { "none" } else { $"($dir)/($label).o" }
    if not (attached $iface | is-empty) {
        error make {msg: $"($iface) has programs attached before the run"}
    }
    # the window outlasts the start of bpftrace and the profile with a margin on both sides
    let window = $secs + 25
    ^bash -c $"setsid nohup ($dir)/progbench -obj ($obj) -label '($label)' -attach ($iface) -n ($n) -warmup 3s -window ($window)s -stats=false > ($out).json 2> ($out).err < /dev/null &"
    if $label != "none" {
        mut seen = false
        for i in 1..180 {
            if not (attached $iface | is-empty) {
                $seen = true
                break
            }
            sleep 500ms
        }
        if not $seen {
            ^pkill -f $"^($dir)/progbench " | complete | ignore
            error make {msg: $"($label) did not attach to ($iface)"}
        }
    }
    # past the warm-up of progbench, so that its window covers every sample
    sleep 6sec
    let before = attached $iface
    let rate0 = ^sysctl -n kernel.perf_event_max_sample_rate | str trim | into int
    let pct0 = ^sysctl -n kernel.perf_cpu_time_max_percent | str trim | into int
    # the rate takes a write only while the percentage is neither 0 nor 100, and at 0 the kernel
    # no longer lowers the rate on its own
    ^sysctl -qw kernel.perf_cpu_time_max_percent=25
    ^sysctl -qw kernel.perf_event_max_sample_rate=100000000
    ^sysctl -qw kernel.perf_cpu_time_max_percent=0
    let t0 = date now
    # the top bit of the instruction pointer tells kernel mode from user mode, and the samples
    # count from the third tick of the interval probe to its tick secs later, since bpftrace
    # takes more than a second to attach the profile probe to every CPU
    let lead = 3
    let prog = (
        'profile:hz:' + ($hz | into string)
        + ' /@on/ { if (reg("ip") >> 63) { @k[ksym(reg("ip"))] = count(); } else { @u[comm] = count(); } }'
        + ' interval:s:1 { @t++; if (@t == ' + ($lead | into string) + ') { @on = 1; }'
        + ' if (@t == ' + (($lead + $secs) | into string) + ') { @on = 0; exit(); } }'
    )
    # a map of bpftrace holds 4096 keys by default and drops the samples of any further address
    let r = with-env {BPFTRACE_MAX_MAP_KEYS: ($keys | into string)} {
        ^timeout ($secs + 60) bpftrace -e $prog | complete
    }
    ^sysctl -qw kernel.perf_cpu_time_max_percent=25
    ^sysctl -qw $"kernel.perf_event_max_sample_rate=($rate0)"
    ^sysctl -qw $"kernel.perf_cpu_time_max_percent=($pct0)"
    let took = ((date now) - $t0) / 1sec
    let after = attached $iface
    $r.stdout | save -f $"($out).txt"
    let rows = $r.stdout | lines | parse --regex '^@(?<m>[ku])\[.*\]: (?<c>\d+)$'
    let held = $rows | where m == "k" | length
    let cpus = ^nproc | str trim | into int
    let samples = $rows | get c | into int | append 0 | math sum
    let want = $hz * $cpus * $secs
    {
        label: $label
        hz: $hz
        secs: $secs
        took: $took
        exit: $r.exit_code
        stderr: ($r.stderr | str trim)
        cpus: $cpus
        keys: $held
        samples: $samples
        want: $want
        limits: [$rate0 $pct0]
        before: $before
        after: $after
    } | to json --raw | save -f $"($out).net"
    # progbench prints its line when the window ends
    for i in 1..240 {
        if (^pgrep -f $"^($dir)/progbench " | complete).exit_code != 0 { break }
        sleep 500ms
    }
    if $r.exit_code != 0 {
        error make {msg: $"bpftrace left ($r.exit_code): ($r.stderr | str trim)"}
    }
    if $held >= $keys or ($r.stderr | str contains "Map full") {
        error make {
            msg: $"the kernel map was full at ($held) addresses, samples are missing"
        }
    }
    if (($samples - $want) | math abs) > $want / 50 {
        error make {msg: $"($samples) samples where ($want) were due"}
    }
    if $label != "none" and (($before | is-empty) or ($after | is-empty)) {
        error make {msg: $"($label) was not attached for the whole profile"}
    }
    if (open --raw $"($out).json" | str trim | is-empty) {
        error make {msg: $"progbench left no line: (open --raw $'($out).err' | str trim)"}
    }
    print $"($label) profiled for ($took) s"
}
