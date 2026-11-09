#!/usr/bin/env bash
# t0 tuning pass driver: loops over measure.nu on the dut under gen.nu floods from the generator
set -u
D="ssh -o BatchMode=yes -o IdentitiesOnly=yes root@spirou-7-kavlan-4.louvain.g5k"
G="ssh -o BatchMode=yes -o IdentitiesOnly=yes root@spirou-8-kavlan-4.louvain.g5k"
GEN="nu /root/workload/gen.nu --iface ens1f0np0 --dst 10.48.0.7 --dstmac e8:eb:d3:fd:ce:ac --flows 1000 --count 4000000000"
gen_start() { $G "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu /root/workload/gen.nu'; setsid nohup $GEN --threads $1 > /tmp/gen.log 2>&1 < /dev/null &"; sleep 14; }
gen_stop() { $G "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu /root/workload/gen.nu'; true"; }
m() { echo "$(date +%T) measure.nu $*"; $D "timeout 300 $1 nu /root/workload/measure.nu --warmup 10 --secs 30 --stat-secs 8 --out /root/res/t0c.jsonl $(printf " %q" "${@:2}") > /dev/null 2>&1; echo exit=\$?"; }
X="iface_slots=1\nring_buf_size=16384"
gen_start 1
m "" --agent rfm --n 1000 --rfm-bpf "stage_events=32\n$X" --label "t0c n1000 st32 mem"
m "" --agent rfm --n 10 --rfm-bpf "stage_events=32\n$X" --label "t0c n10 st32 mem"
m "" --agent rfm --n 100 --rfm-bpf "stage_events=32\n$X" --label "t0c n100 st32 mem"
m "" --agent rfm --n 100 --rfm-bpf "sampled_only=true\nstage_events=32\nring_buf_size=16384" --label "t0c n100 sampled st32 ring16k"
gen_start 4
m "" --agent rfm --n 10 --rfm-bpf "stage_events=32\n$X" --label "t0c-hi n10 st32 mem"
m "" --agent rfm --n 10 --rfm-bpf "sampled_only=true\nstage_events=32\nring_buf_size=16384" --label "t0c-hi n10 sampled st32 ring16k"
m "" --agent netobserv --n 10 --label "t0c-hi n10 neto"
gen_stop
echo "$(date +%T) t0c done"
