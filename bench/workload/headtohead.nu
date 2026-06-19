#!/usr/bin/env nu

# Head-to-head agent comparison on a real NIC under a sustained external flood
# (start gen.nu on the peer FIRST). For each agent it reports system-wide busy
# cores (delta of /proc/stat, the fair total: NIC softirq + capture + userspace)
# and the agent's own process cores, over a fixed window. rfm samples in-kernel
# (only sampled packets reach userspace); pmacctd/softflowd are libpcap tools
# that copy EVERY packet to userspace and sample after, so they pay the full
# per-packet capture cost regardless of sampling. Run under:
#   nix shell nixpkgs#softflowd nixpkgs#pmacct -c nu workload/headtohead.nu
# Run detached; baselines' libpcap stats land in /tmp/{sfd,pmd}.log.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

# non-idle jiffies across all CPUs from /proc/stat
def cpu-busy [] {
    let f = (open --raw /proc/stat | lines | where {|l| $l | str starts-with "cpu "} | first
    | split row ' ' | where {|x| $x != ""})
    let v = $f | skip 1 | each {|x| $x | into int}
    let i1 = $v | get 3
    let i2 = $v | get 4
    let total = $v | math sum
    {
        busy: ($total - $i1 - $i2)
    }
}

# measure system busy cores and one process's cores over secs
def measure [pidpat: string, secs: int] {
    let clk = (^getconf CLK_TCK | into int)
    let pid = (
        ^pgrep -x $pidpat
        | complete
        | get stdout
        | lines
        | get 0?
        | default "0"
        | str trim
        | into int
    )
    let b0 = (cpu-busy)
    let p0 = (if $pid > 0 { proc-cpu $pid } else { 0 })
    let t0 = (date now)
    sleep ($secs * 1sec)
    let dur = (((date now) - $t0) / 1sec)
    let b1 = (cpu-busy)
    let p1 = (if $pid > 0 { proc-cpu $pid } else { 0 })
    {
        sys_cores: ((($b1.busy - $b0.busy) / $clk / $dur) | math round --precision 3)
        proc_cores: (
            if $pid > 0 {
                (($p1 - $p0) / $clk / $dur) | math round --precision 3
            } else { 0.0 }
        )
    }
}

def main [
  --iface: string = "ens3f0np0"
  --secs: int = 15
  --n: int = 100          # matched sampling rate
] {
    $'pcap_interface: ($iface)
aggregate: src_host,dst_host,src_port,dst_port,proto
plugins: nfprobe
nfprobe_receiver: 127.0.0.1:9995
nfprobe_version: 10
sampling_rate: ($n)
' | save --force /tmp/pmacctd.conf
    bpf-stats true

    # baseline: no agent (NIC RX softirq cost at the offered load)
    let base = (measure "no-such-process-xyzzy" $secs)

    # rfm at matched N
    let toml = $'[agent]
interfaces=["($iface)"]
[agent.bpf]
sample_rate=($n)
[agent.prometheus]
host="127.0.0.1"
port=9669
'
    let r = (rfm-start $toml)
    sleep 3sec
    let rfmm = (measure "rfm" $secs)
    let drops = metric-val (metrics) "rfm_collector_dropped_events_total" | into int
    rfm-stop $r.jid

    # softflowd (libpcap), matched 1-in-N sampling, foreground
    ^rm -f /tmp/sfd.log
    ^bash -c $"nohup softflowd -i ($iface) -n 127.0.0.1:9995 -v 10 -s ($n) -d >/tmp/sfd.log 2>&1 &"
    sleep 3sec
    let sfdm = (measure "softflowd" $secs)
    ^pkill -INT -x softflowd | complete | ignore
    sleep 2sec

    # pmacctd (libpcap), matched 1-in-N sampling, foreground
    ^rm -f /tmp/pmd.log
    ^bash -c "nohup pmacctd -f /tmp/pmacctd.conf >/tmp/pmd.log 2>&1 &"
    sleep 4sec
    let pmdm = (measure "pmacctd" $secs)
    ^pkill -INT -x pmacctd | complete | ignore
    sleep 2sec

    bpf-stats false
    let rows = [
        {
            agent: "none (baseline)"
            sys_cores: $base.sys_cores
            proc_cores: 0.0
            note: "NIC RX softirq only"
        }
        {
            agent: $"rfm N=($n)"
            sys_cores: $rfmm.sys_cores
            proc_cores: $rfmm.proc_cores
            note: $"in-kernel sample; ring drops ($drops)"
        }
        {
            agent: $"softflowd s=($n)"
            sys_cores: $sfdm.sys_cores
            proc_cores: $sfdm.proc_cores
            note: "libpcap; see /tmp/sfd.log"
        }
        {
            agent: $"pmacctd s=($n)"
            sys_cores: $pmdm.sys_cores
            proc_cores: $pmdm.proc_cores
            note: "libpcap; see /tmp/pmd.log"
        }
    ]
    $rows | to json | save --force /tmp/headtohead.json
    $rows
}
