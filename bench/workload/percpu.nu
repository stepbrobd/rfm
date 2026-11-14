#!/usr/bin/env nu

# One JSON line of what every CPU of this host did since boot, appended to
# --out, so that two calls around a window give each CPU's share of it: the
# microseconds in each idle state, the softirqs of the hrtimer, timer and
# receive vectors, and the local timer and rescheduling interrupts. A bpf
# timer expires in the hrtimer softirq of the CPU it is pinned to, and the
# idle times tell a CPU that sleeps deep from one that something keeps waking.

# the counts of one row of /proc/softirqs or /proc/interrupts, one per CPU
def row [path: string, name: string, cpus: int] {
    let hit = open --raw $path | lines | where {|l| ($l | str trim) | str starts-with $"($name):" }
    if ($hit | is-empty) { return [] }
    $hit | first | str trim | split row --regex '\s+' | skip 1 | take $cpus | each {|x| $x | into int }
}

def main [
    --label: string = "" # copied into the line
    --out: string = "/tmp/percpu.jsonl"
] {
    let cpus = ls /sys/devices/system/cpu | get name | where {|p| $p =~ '/cpu\d+$' } | length
    let states = ls /sys/devices/system/cpu/cpu0/cpuidle | get name | each {|p| $p | path basename } | sort
    let idle = $states | each {|s|
        {
            name: (open --raw $"/sys/devices/system/cpu/cpu0/cpuidle/($s)/name" | str trim)
            us: (0..($cpus - 1) | each {|c| open --raw $"/sys/devices/system/cpu/cpu($c)/cpuidle/($s)/time" | str trim | into int })
        }
    }
    {
        label: $label
        ts: ((date now | into int) / 1e9)
        cpus: $cpus
        idle: $idle
        softirq: {
            hrtimer: (row /proc/softirqs HRTIMER $cpus)
            timer: (row /proc/softirqs TIMER $cpus)
            net_rx: (row /proc/softirqs NET_RX $cpus)
        }
        irq: {
            loc: (row /proc/interrupts LOC $cpus)
            res: (row /proc/interrupts RES $cpus)
        }
    } | to json --raw | save --append $out
    "\n" | save --append $out
}
