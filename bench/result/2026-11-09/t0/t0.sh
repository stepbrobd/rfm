#!/usr/bin/env bash
# t0 tuning pass driver: loops over measure.nu on the dut under gen.nu floods from the generator
set -u
D="ssh -o BatchMode=yes -o IdentitiesOnly=yes root@spirou-7-kavlan-4.louvain.g5k"
G="ssh -o BatchMode=yes -o IdentitiesOnly=yes root@spirou-8-kavlan-4.louvain.g5k"
GEN="nu /root/workload/gen.nu --iface ens1f0np0 --dst 10.48.0.7 --dstmac e8:eb:d3:fd:ce:ac --flows 1000 --count 4000000000"
gen_start() { $G "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu /root/workload/gen.nu'; setsid nohup $GEN --threads $1 > /tmp/gen.log 2>&1 < /dev/null &"; sleep 14; }
gen_stop() { $G "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu /root/workload/gen.nu'; true"; }
m() { echo "$(date +%T) measure.nu $*"; $D "timeout 300 $1 nu /root/workload/measure.nu --warmup 10 --secs 30 --stat-secs 8 --out /root/res/t0.jsonl $(printf " %q" "${@:2}") > /dev/null 2>&1; echo exit=\$?"; }
$D 'pkill iperf3; rm -f /root/res/t0.jsonl'; $G 'pkill iperf3; true'
gen_start 1
m "" --agent none --label t0-base
for st in 1 16 32; do for ring in 0 1048576; do m "" --agent rfm --n 1 --rfm-bpf "stage_events=$st\nring_buf_size=$ring" --label "t0 n1 st$st ring$ring"; done; done
m "env GOGC=400" --agent rfm --n 1 --rfm-bpf "stage_events=16\nring_buf_size=1048576" --label "t0 n1 st16 ring1M gogc400"
for st in 1 16; do m "" --agent rfm --n 10 --rfm-bpf "stage_events=$st" --label "t0 n10 st$st"; m "env GOGC=400" --agent rfm --n 10 --rfm-bpf "stage_events=$st" --label "t0 n10 st$st gogc400"; done
for st in 1 16; do m "" --agent rfm --n 100 --rfm-bpf "stage_events=$st" --label "t0 n100 st$st"; done
for ring in 16384 4096; do m "" --agent rfm --n 100 --rfm-bpf "ring_buf_size=$ring" --label "t0 n100 ring$ring"; done
m "" --agent rfm --n 100 --rfm-bpf "sampled_only=true" --label "t0 n100 sampled"
m "" --agent rfm --n 100 --rfm-bpf "iface_slots=1" --label "t0 n100 slots1"
m "env GOGC=400" --agent rfm --n 100 --label "t0 n100 gogc400"
m "" --agent netobserv --n 100 --label "t0 n100 neto"
m "" --agent hsflowd --n 100 --label "t0 n100 hsf"
m "" --agent none --label t0-base-end
gen_start 4
m "" --agent none --label "t0-hi base"
for st in 1 16; do m "" --agent rfm --n 100 --rfm-bpf "stage_events=$st" --label "t0-hi n100 st$st"; done
m "" --agent rfm --n 100 --rfm-bpf "sampled_only=true" --label "t0-hi n100 sampled"
m "" --agent netobserv --n 100 --label "t0-hi n100 neto"
m "" --agent rfm --n 1 --rfm-bpf "stage_events=32\nring_buf_size=1048576" --label "t0-hi n1 st32 ring1M"
m "" --agent rfm --n 1 --rfm-bpf "stage_events=1\nring_buf_size=1048576" --label "t0-hi n1 st1 ring1M"
gen_stop
echo "$(date +%T) t0 done"
