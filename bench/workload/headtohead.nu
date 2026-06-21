#!/usr/bin/env nu

# Head-to-head agent comparison on a real NIC under a sustained external flood
# (start gen.nu on the peer FIRST). For each agent it reports system-wide busy
# cores (delta of /proc/stat, the fair total: NIC softirq + capture + userspace)
# and the agent's own process cores, over a fixed window. rfm samples in-kernel
# (only sampled packets reach userspace); pmacctd/softflowd are libpcap tools
# that copy EVERY packet to userspace and sample after, so they pay the full
# per-packet capture cost regardless of sampling. We also compare two in-kernel
# eBPF agents: netobserv-ebpf-agent (per-CPU HASH flow aggregation in the kernel
# -- the opposite design point to rfm) run standalone with EXPORT=direct-flp (no
# collector needed), and hsflowd in EPCAP mode (eBPF/TCX in-kernel 1-in-N
# sampling, no per-flow kernel state -- the same design point as rfm, sFlow
# export). pmacct/softflowd come from nixpkgs; netobserv/hsflowd are not in
# nixpkgs and ship in the bench image (bench/{netobserv,hsflowd}.nix), already on
# PATH on the deployed node. Run detached; logs land in /tmp/{sfd,pmd,neto,hsf}.log.

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
    # precompute into single-pipeline lets so the record values are bare vars --
    # the formatter strips parens off record-value pipelines and breaks the parse.
    let dbusy = $b1.busy - $b0.busy
    let bcores = $dbusy / $clk / $dur | math round --precision 3
    let pcores = (
        if $pid > 0 {
            ($p1 - $p0) / $clk / $dur | math round --precision 3
        } else { 0.0 }
    )
    {sys_cores: $bcores, proc_cores: $pcores}
}

# like measure, but for a known pid -- used for agents whose comm exceeds the
# 15-char /proc/<pid>/comm limit that pgrep -x matches against (e.g.
# netobserv-ebpf-agent truncates to "netobserv-ebpf-").
def measure-pid [pid: int, secs: int] {
    let clk = (^getconf CLK_TCK | into int)
    let b0 = (cpu-busy)
    let p0 = (if $pid > 0 { proc-cpu $pid } else { 0 })
    let t0 = (date now)
    sleep ($secs * 1sec)
    let dur = (((date now) - $t0) / 1sec)
    let b1 = (cpu-busy)
    let p1 = (if $pid > 0 { proc-cpu $pid } else { 0 })
    # precompute into single-pipeline lets so the record values are bare vars --
    # the formatter strips parens off record-value pipelines and breaks the parse.
    let dbusy = $b1.busy - $b0.busy
    let bcores = $dbusy / $clk / $dur | math round --precision 3
    let pcores = (
        if $pid > 0 {
            ($p1 - $p0) / $clk / $dur | math round --precision 3
        } else { 0.0 }
    )
    {sys_cores: $bcores, proc_cores: $pcores}
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

    # netobserv-ebpf-agent (eBPF, in-kernel per-CPU HASH aggregation): the
    # opposite design point to rfm. Standalone/env-driven; EXPORT=direct-flp
    # writes flows to stdout (discarded) so no collector is needed. Its comm is
    # too long for pgrep -x, so capture the pid (exec keeps the same pid).
    ^rm -f /tmp/neto.log /tmp/neto.pid
    let flp = '{"pipeline":[{"name":"writer","follows":"preset-ingester"}],"parameters":[{"name":"writer","write":{"type":"stdout"}}]}'
    let neto_sh = $"#!/usr/bin/env bash
export INTERFACES=($iface)
export SAMPLING=($n)
export EXPORT=direct-flp
export FLP_CONFIG='($flp)'
exec netobserv-ebpf-agent
"
    $neto_sh | save --force /tmp/neto-run.sh
    ^chmod +x /tmp/neto-run.sh
    ^bash -c "nohup /tmp/neto-run.sh >/dev/null 2>/tmp/neto.log & echo $! > /tmp/neto.pid"
    sleep 4sec
    let neto_pid = open /tmp/neto.pid | str trim | into int
    let netom = (measure-pid $neto_pid $secs)
    ^kill -INT $neto_pid | complete | ignore
    sleep 2sec

    # hsflowd EPCAP (eBPF/TCX, in-kernel 1-in-N sampling, no per-flow kernel
    # state) -- the same design point as rfm; exports sFlow to a no-op local
    # collector. The binary defaults to /etc/hsflowd/modules, so point -l at the
    # package's own module dir (next to its bin/).
    let hsf_mod = (
        which hsflowd
        | get 0.path
        | path dirname
        | path join ".." "lib" "hsflowd" "modules"
        | path expand
    )
    $'sflow {
  agent = ($iface)
  collector { ip = 127.0.0.1  udpport = 6343 }
  epcap { dev = ($iface)  sampling = ($n) }
}
' | save --force /tmp/hsflowd.conf
    ^rm -f /tmp/hsf.log
    ^bash -c $"nohup hsflowd -d -f /tmp/hsflowd.conf -l ($hsf_mod) > /tmp/hsf.log 2>&1 &"
    sleep 4sec
    let hsfm = (measure "hsflowd" $secs)
    ^pkill -INT -x hsflowd | complete | ignore
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
        {
            agent: $"netobserv N=($n)"
            sys_cores: $netom.sys_cores
            proc_cores: $netom.proc_cores
            note: "eBPF in-kernel hash; direct-flp"
        }
        {
            agent: $"hsflowd epcap s=($n)"
            sys_cores: $hsfm.sys_cores
            proc_cores: $hsfm.proc_cores
            note: "eBPF/TCX in-kernel sample; sFlow"
        }
    ]
    $rows | to json | save --force /tmp/headtohead.json
    $rows
}
