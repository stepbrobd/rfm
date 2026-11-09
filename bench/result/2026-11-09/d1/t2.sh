#!/usr/bin/env bash
# checks before the night: the b2 points span the skb aggregation range, and gen.nu --queue-xmit
# reaches tc egress. Loops over measure.nu and gen.nu only.
set -u
D="ssh -o BatchMode=yes root@spirou-7-kavlan-4.louvain.g5k"
G="ssh -o BatchMode=yes root@spirou-8-kavlan-4.louvain.g5k"
m() { $D "timeout 200 nu /root/workload/measure.nu --iface ens1f0np0 --warmup 4 --secs 6 --stat-secs 3 --out /root/res/t2.jsonl $(printf ' %q' "$@") > /dev/null 2>> /root/res/t2.err; echo exit=\$?"; }
istop() { $D 'pkill -x iperf3; true'; $G 'pkill -x iperf3; true'; sleep 2; }
$D 'rm -f /root/res/t2.jsonl'
for pt in "128|-b 10M -N -l 1448" "128|-b 2M -N -l 1448"; do
    P=${pt%%|*}; X=${pt#*|}; istop
    $D 'iperf3 -s -D'; $G "setsid nohup iperf3 -c 10.48.0.7 -P $P $X -t 86400 > /tmp/iperf.log 2>&1 < /dev/null &"; sleep 8
    m --agent netobserv --n 100 --counts --label "t2 rx P$P $X netobserv"
done
for X in "-N -l 1448 -b 100M" "-N -l 8K -b 100M" "-N -l 32K -b 300M" "-N -l 64K -b 1G"; do
    istop
    $G 'iperf3 -s -D'; $D "setsid nohup iperf3 -c 10.48.0.8 -P 8 $X -t 86400 > /tmp/iperf.log 2>&1 < /dev/null &"; sleep 8
    m --agent netobserv --n 100 --counts --label "t2 tx P8 $X netobserv"
done
istop
$D "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu /root/workload/gen.nu'; setsid nohup nu /root/workload/gen.nu --iface ens1f0np0 --dst 10.48.0.8 --dstmac e8:eb:d3:fd:cf:0c --count 4000000000 --threads 1 --queue-xmit > /tmp/gen.log 2>&1 < /dev/null &"
sleep 15
m --agent rfm --n 100 --rfm-bpf 'stage_events=32\niface_slots=1\nring_buf_size=16384' --label "t2 udp tx queue_xmit rfm"
m --agent none --n 100 --label "t2 udp tx queue_xmit none"
$D "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu /root/workload/gen.nu'; true"
echo t2 done
