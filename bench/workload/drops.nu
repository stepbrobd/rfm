#!/usr/bin/env nu

# dut side under the peer's flood (start gen.nu first), follows one agent once a second from its start and records the ring drops of rfm_flow_drops in total and per cpu, its rss and the cpus of its busiest threads, with the go gc trace in /tmp/rfm.log, run detached and read /tmp/drops.json after

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

# cpu and lifetime cpu percent of the three busiest threads of a pid, as ps -L computes them
def busy-threads [pid: int] {
    # an external piped on inside a def does not raise on a nonzero exit, complete makes it explicit
    let r = (^ps -L -o psr=,pcpu= -p $pid | complete)
    if $r.exit_code != 0 {
        error make {
            msg: $"ps -L -p ($pid) failed with exit code ($r.exit_code): ($r.stderr | str trim)"
        }
    }
    $r.stdout
    | lines
    | parse --regex '^\s*(?<cpu>\d+)\s+(?<pcpu>[\d.]+)'
    | into int cpu
    | into float pcpu
    | sort-by pcpu --reverse
    | first 3
}

def main [
  --iface: string = "eno1np0"
  --n: int = 1          # sample rate
  --secs: int = 60      # seconds to follow the agent, one row each
  --ring: int = 0       # ring_buf_size in bytes of each per cpu ring, 0 keeps the default
  --cpus: string = ""   # taskset cpu list for the agent, empty runs it anywhere
] {
    if $secs < 1 {
        error make {msg: "--secs must be at least 1"}
    }
    # a stray agent would add its own rfm_flow_drops map
    ^pkill -KILL -f "rfm agent" | complete | ignore
    sleep 1sec
    # ring_buf_size only when set, 0 keeps the agent's default
    let ring_toml = if $ring > 0 { $"ring_buf_size=($ring)\n" } else { "" }
    let toml = $'[agent]
interfaces=["($iface)"]
[agent.bpf]
sample_rate=($n)
($ring_toml)[agent.prometheus]
host="127.0.0.1"
port=9669
'
    # a run that fails before its first row leaves an empty series in place of the last run's
    [] | to json | save --force /tmp/drops.json
    let t0 = (date now)
    let r = with-env {GODEBUG: "gctrace=1"} { rfm-start $toml --cpus $cpus }
    let ring_s = if $ring > 0 {
        $ring | into string
    } else {
        "default"
    }
    let cpus_s = if ($cpus | is-empty) { "all" } else { $cpus }
    print $"pid ($r.pid) ring ($ring_s) cpus ($cpus_s)"
    mut rows = []
    try {
        for i in 1..$secs {
            let t = ((date now) - $t0) / 1sec | math round --precision 3
            let rss = (proc-rss $r.pid)
            let per = (flow-drops)
            let busy = (busy-threads $r.pid)
            let total = $per | get drops | math sum
            let hit = $per | where drops > 0
            let rss_mb = $rss / 1024 | math round --precision 1
            $rows = $rows | append {
                "t": $t
                "drops": $total
                "drop cpus": $hit
                "rss MB": $rss_mb
                "busy threads": $busy
            }
            # rewritten each second, which keeps the series of a run that fails
            $rows | to json | save --force /tmp/drops.json
            sleep 1sec
        }
    } finally {
        # job kill fails once the agent died, pkill by name covers that case
        try {
            rfm-stop $r.jid
        } catch {
            ^pkill -f "rfm agent" | complete | ignore
        }
    }
    $rows
}
