#!/usr/bin/env nu

# DPDK line-rate generator (run on the TRAFFIC node). Floods 64B
# txonly-multi-flow at 25GbE line rate toward a DUT via dpdk-testpmd. This is the
# nu wrapper for the line-rate leg that the kernel-pktgen gen.nu cannot reach; it
# encapsulates the two operational steps the raw command needs:
#   1. allocate 2M hugepages at runtime (the kadeploy kernel_params override NixOS
#      boot.kernelParams, so the node boots without them);
#   2. clear /dev/hugepages/rtemap_* left by a SIGKILL'd testpmd -- those orphans
#      pin every hugepage so the next EAL init fails and the new testpmd never
#      floods (TX frozen at the initial burst). A partial rm is not enough, so we
#      fully reset nr_hugepages then re-allocate.
# mlx5 is bifurcated: DPDK transmits while the kernel keeps the NIC bound (no vfio,
# no IOMMU), so only the data PCI port is allowlisted (-a) and the control NIC is
# untouched. The flood is launched detached and keeps running after this returns;
# stop it with `nu dpdk.nu --stop`.
#
#   nu dpdk.nu --pci 0000:18:00.0 --peer 98:03:9b:b0:bf:ce --self-ip 10.16.0.91 --dst-ip 10.16.0.55
#   nu dpdk.nu --stop

const HP = "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"

# remove every orphan rtemap hugepage file a prior testpmd left behind
def clear-rtemap [] {
    ls /dev/hugepages 2>/dev/null
    | where {|f| ($f.name | path basename) | str starts-with "rtemap_"}
    | each {|f| rm -f $f.name }
    | ignore
}

# full hugepage reset then (re)allocate n 2M pages, so a fresh EAL init can map them
def hugepages-reset [n: int] {
    "0\n" | save --raw --force $HP
    sleep 500ms
    clear-rtemap
    $"($n)\n" | save --raw --force $HP
}

# cumulative TX-packets samples printed by testpmd's --stats-period
def tx-samples [log: string] {
    open --raw $log
    | lines
    | where {|l| $l =~ 'TX-packets:'}
    | each {|l| $l | parse --regex 'TX-packets:\s+(?<n>\d+)' | get n.0? | default "0" | into int}
}

def main [
  --pci: string = "0000:18:00.0"   # data-port PCI address (mlx5)
  --peer: string                   # DUT NIC MAC (--eth-peer); required to start
  --self-ip: string = "10.16.0.91" # generator data IP (tx-ip source)
  --dst-ip: string = "10.16.0.55"  # DUT data IP (tx-ip dest)
  --cores: string = "0-8"          # EAL lcore list
  --txq: int = 8                   # TX queues
  --rxq: int = 8                   # RX queues
  --nb-cores: int = 8              # forwarding cores
  --mbufs: int = 262144            # total mbuf pool
  --size: int = 64                 # frame size (bytes)
  --hugepages: int = 8192          # number of 2M pages to allocate
  --period: int = 2                # testpmd --stats-period (s); also the rate window
  --settle: int = 10               # seconds to flood before sampling TX rate
  --log: string = "/tmp/dpdk.log"  # testpmd output
  --stop                           # tear the flood down and exit
] {
    if $stop {
        ^pkill -KILL -f dpdk-testpmd | complete | ignore
        sleep 1sec
        clear-rtemap
        return {stopped: true}
    }
    if ($peer | is-empty) {
        error make {msg: "--peer (DUT NIC MAC) is required to start the flood"}
    }

    ^pkill -KILL -f dpdk-testpmd | complete | ignore
    sleep 2sec
    hugepages-reset $hugepages

    let cmd = ([
        "dpdk-testpmd" "-l" $cores "-n" "4" "-a" $pci "--"
        "--forward-mode=txonly" "--txonly-multi-flow" "--auto-start"
        $"--eth-peer=0,($peer)" $"--tx-ip=($self_ip),($dst_ip)"
        $"--txq=($txq)" $"--rxq=($rxq)" $"--nb-cores=($nb_cores)"
        $"--txpkts=($size)" $"--total-num-mbufs=($mbufs)" $"--stats-period=($period)"
    ] | str join " ")

    ^bash -c $"setsid nohup ($cmd) > ($log) 2>&1 < /dev/null &"
    sleep ($settle * 1sec)

    let xs = (tx-samples $log)
    let nsamp = $xs | length
    let last = $xs | last | default 0
    let prev = if $nsamp >= 2 { ($xs | get ($nsamp - 2)) } else { 0 }
    let dtx = $last - $prev
    let tx_mpps = (
        if ($nsamp >= 2) and ($period > 0) { ($dtx / $period / 1000000 | math round --precision 2) } else { 0 }
    )
    let running = (not ((
        ^pgrep -f dpdk-testpmd
        | complete
        | get stdout
        | str trim
    ) | is-empty))

    {
        pci: $pci
        peer: $peer
        tx_ip: $"($self_ip)->($dst_ip)"
        size: $size
        txq: $txq
        nb_cores: $nb_cores
        running: $running
        tx_total: $last
        tx_mpps: $tx_mpps
        log: $log
    }
}
