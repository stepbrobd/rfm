#!/usr/bin/env nu

# Multi-queue kernel-pktgen generator (run on the TRAFFIC node). Drives many UDP
# flows out a real NIC across T TX queues toward a DUT. clone_skb=0 by default
# so each packet is rebuilt and the UDP source port varies (UDPSRC_RND) -> the
# DUT's hardware RSS spreads the flows across its RX queues. --clone resends each
# skb that many times and --burst batches the doorbell (xmit_more) for a higher
# rate, at the cost of runs of one source port. Reports achieved aggregate pps.
# For a sustained flood run detached with a large --count.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

# the IPv4 address n above a
def ip-add [a: string, n: int] {
    let o = $a | split row "." | each {|x| $x | into int }
    let v = (($o.0 * 16777216) + ($o.1 * 65536) + ($o.2 * 256) + $o.3 + $n)
    [
        ($v // 16777216 mod 256)
        ($v // 65536 mod 256)
        ($v // 256 mod 256)
        ($v mod 256)
    ] | each {|x| $x | into string } | str join "."
}

def main [
  --iface: string = "ens3f0np0"  # generator NIC
  --dst: string                  # DUT IP
  --dstmac: string               # DUT NIC MAC
  --threads: int = 4             # TX queues / kpktgend threads
  --size: int = 60               # packet size (bytes)
  --count: int = 5000000         # packets per thread
  --flows: int = 1000            # distinct UDP source ports
  --rate: int = 0                # per-device Mbit/s cap, 0 = unlimited
  --clone: int = 0               # clone_skb, sends of one skb before a rebuild
  --burst: int = 1               # packets per doorbell
  --srcips: int = 1              # distinct IPv4 source addresses from --srcbase, flows are --flows times this
  --srcbase: string = "10.200.0.1" # first IPv4 source address of a --srcips range
  --dst6: string = ""            # DUT IPv6 address, sends IPv6 in place of IPv4 when set
  --src6: string = ""            # generator IPv6 source address for --dst6
  --vlan: int = -1               # 802.1Q VLAN id of every frame, -1 sends untagged
  --queue-xmit                   # send through dev_queue_xmit, so tc egress and the qdisc see every packet, where the default hands them to the driver
] {
    ^modprobe pktgen
    let spmin = 10000
    let spmax = ($spmin + $flows - 1)
    # udp_src_max is 16 bits, a larger value wraps below udp_src_min and pktgen then sends from one port
    if $spmax > 65535 {
        error make {
            msg: $"--flows ($flows) needs source ports up to ($spmax), at most (65536 - $spmin) flows fit"
        }
    }
    # start runs every thread with a device, so clear the ones above --threads left by an earlier run
    glob $"($env.PG)/kpktgend_*" | each {|t| pg $t "rem_device_all" } | ignore
    0..($threads - 1) | each {|i|
    pg $"($env.PG)/kpktgend_($i)" $"add_device ($iface)@($i)"
    let d = $"($env.PG)/($iface)@($i)"
    pg $d $"count ($count)"
    pg $d $"clone_skb ($clone)"
    pg $d $"pkt_size ($size)"
    pg $d "delay 0"
    if ($dst6 | is-empty) {
        pg $d $"dst ($dst)"
    } else {
        pg $d $"dst6 ($dst6)"
        pg $d $"src6 ($src6)"
    }
    if $srcips > 1 {
        pg $d $"src_min ($srcbase)"
        pg $d $"src_max (ip-add $srcbase ($srcips - 1))"
        pg $d "flag IPSRC_RND"
    }
    if $vlan >= 0 { pg $d $"vlan_id ($vlan)" }
    pg $d $"dst_mac ($dstmac)"
    # each thread owns tx queue i, threads that share a queue serialize on its lock
    pg $d $"queue_map_min ($i)"
    pg $d $"queue_map_max ($i)"
    pg $d "udp_dst_min 9"
    pg $d "udp_dst_max 9"
    pg $d $"udp_src_min ($spmin)"
    pg $d $"udp_src_max ($spmax)"
    pg $d "flag UDPSRC_RND"
    if $burst > 1 { pg $d $"burst ($burst)" }
    if $queue_xmit { pg $d "xmit_mode queue_xmit" }
    if $rate > 0 { pg $d $"rate ($rate)" }
  }
    pg $"($env.PG)/pgctrl" "start"
    let pps = (0..($threads - 1) | each {|i|
    open --raw $"($env.PG)/($iface)@($i)" | lines | where {|l| $l =~ 'pps'} | get 0?
    | default "" | parse --regex '(?<p>\d+)pps' | get p.0? | default "0" | into int
  } | math sum)
    {
        threads: $threads
        size: $size
        flows: ($flows * $srcips)
        agg_pps: $pps
    }
}
