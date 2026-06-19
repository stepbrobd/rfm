#!/usr/bin/env nu

# Multi-queue kernel-pktgen generator (run on the TRAFFIC node). Drives many UDP
# flows out a real NIC across T TX queues toward a DUT. clone_skb=0 so each
# packet is rebuilt and the UDP source port varies (UDPSRC_RND) -> the DUT's
# hardware RSS spreads the flows across its RX queues. Reports achieved
# aggregate pps. For a sustained flood run detached with a large --count.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

def main [
  --iface: string = "ens3f0np0"  # generator NIC
  --dst: string                  # DUT IP
  --dstmac: string               # DUT NIC MAC
  --threads: int = 4             # TX queues / kpktgend threads
  --size: int = 60               # packet size (bytes)
  --count: int = 5000000         # packets per thread
  --flows: int = 1000            # distinct UDP source ports
  --rate: int = 0                # per-device Mbit/s cap, 0 = unlimited
] {
    ^modprobe pktgen
    let spmin = 10000
    let spmax = ($spmin + $flows - 1)
    0..($threads - 1) | each {|i|
    pg $"($env.PG)/kpktgend_($i)" "rem_device_all"
    pg $"($env.PG)/kpktgend_($i)" $"add_device ($iface)@($i)"
    let d = $"($env.PG)/($iface)@($i)"
    pg $d $"count ($count)"
    pg $d "clone_skb 0"
    pg $d $"pkt_size ($size)"
    pg $d "delay 0"
    pg $d $"dst ($dst)"
    pg $d $"dst_mac ($dstmac)"
    pg $d "udp_dst_min 9"
    pg $d "udp_dst_max 9"
    pg $d $"udp_src_min ($spmin)"
    pg $d $"udp_src_max ($spmax)"
    pg $d "flag UDPSRC_RND"
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
        flows: $flows
        agg_pps: $pps
    }
}
