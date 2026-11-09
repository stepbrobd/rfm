#!/usr/bin/env bash
# rfm campaign driver for two spirou nodes in a routed kavlan, run detached on the louvain
# frontend. It only loops over the nu harness calls (measure.nu, gen.nu, progbench*.nu, realnic.nu,
# rss.nu, dpdk.nu) and the iperf3 generator, which has no harness, logs every remote command, and
# copies the json lines to <outdir> after each phase.
#
# usage: campaign.sh <job id> <outdir> [phase ...]
#   the first host of the job is the dut, the second the generator. Control goes over the
#   production port, test traffic over ens1f0np0 in the kavlan only.
# phases, in this order by default:
#   setup b5 b1 b3 b4 b7 b2 b12 b8 b9 b10 b11 more more2
# and pm, the B3 cells with the dut at its default power settings and with turbo and C6 off,
# named on its own
# SRC names a directory on the frontend that holds workload/ and progbench/. DRY=1 runs every
# phase with one round and windows of a few seconds, to check the commands before a night.
set -u

JOB=$1
OUT=$2
shift 2
PHASES=${*:-"setup b5 b1 b3 b4 b7 b2 b12 b8 b9 b10 b11 more more2"}
IF=ens1f0np0
CTL_IF=ens1f1np1
SRC=${SRC:-$HOME/rfm-bench}
W=/root/workload
PB=/root/progbench
# the night deploy regenerates host keys, so known_hosts would refuse the second job
SSH="ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ServerAliveInterval=15 -o ConnectTimeout=20"
SCP="scp -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

# rfm's favorable configuration, picked by the tuning pass t0 on job 20518, \n between toml lines
RFM_EXACT=${RFM_EXACT:-'stage_events=32\niface_slots=1\nring_buf_size=16384'}
RFM_SAMPLED=${RFM_SAMPLED:-'sampled_only=true\nstage_events=32\nring_buf_size=16384'}
RFM_N1=${RFM_N1:-'stage_events=32\niface_slots=1'}
RFM_ACC=${RFM_ACC:-$RFM_EXACT}
RFM_MEM=${RFM_MEM:-'stage_events=32\niface_slots=1\nring_buf_size=4096'}
RFM_ENV=${RFM_ENV:-''}
BIG='[agent.collector]\nmax_flows=2097152'

R3="1 2 3"
R2="1 2"
TRIALS=7
ROUNDS=3
WIN=20s
SECS=20
QS='1 2 4 8 16 32 63'
CHANGES=12
STEP=40
if [ "${DRY:-0}" = 1 ]; then
    R3=1
    R2=1
    TRIALS=1
    ROUNDS=1
    WIN=3s
    SECS=3
    QS='1 63'
    CHANGES=3
    STEP=20
fi

mkdir -p "$OUT/res"
LOG=$OUT/campaign.log
log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

# wait for the job to run and its deploy to finish
while :; do
    st=$(oarstat -fj "$JOB" 2>/dev/null | awk -F' = ' '$1 ~ /^ *state$/ {print $2}')
    [ "$st" = Running ] && break
    case $st in
    Error | Terminated)
        log "job $JOB is $st"
        exit 1
        ;;
    esac
    sleep 30
done
for _ in $(seq 1 120); do
    grep -q 'deploy exit' ~/rfm-kavlan-"$JOB".log 2>/dev/null && break
    sleep 20
done
VLAN=$(kavlan -V -j "$JOB")
HOSTS=$(oarstat -fj "$JOB" | awk -F' = ' '/assigned_hostnames/{print $2}' | tr '+' ' ')
if ! grep -q 'deploy exit=0' ~/rfm-kavlan-"$JOB".log; then
    # one more deploy of the same image on both nodes
    log "deploy failed: $(tail -1 ~/rfm-kavlan-"$JOB".log), retrying"
    printf '%s\n' $HOSTS > "$OUT/nodes"
    OAR_JOB_ID=$JOB kadeploy3 -a ~/g5k-image/nixos-x86_64-linux.yaml -f "$OUT/nodes" --vlan "$VLAN" >> "$LOG" 2>&1 || {
        log "deploy retry failed"
        exit 1
    }
fi
DUTN=$(echo "$HOSTS" | awk '{print $1}' | cut -d. -f1)
GENN=$(echo "$HOSTS" | awk '{print $2}' | cut -d. -f1)
log "job $JOB vlan $VLAN dut $DUTN gen $GENN phases: $PHASES"

# the production address of a node for control, read through its kavlan name
prod() { $SSH root@"$1"-kavlan-"$VLAN".louvain.grid5000.fr "ip -4 -j addr show $CTL_IF | jq -r '.[0].addr_info[0].local'" < /dev/null 2> /dev/null; }
DUTC=""
GENC=""
for _ in $(seq 1 20); do
    DUTC=$(prod "$DUTN")
    GENC=$(prod "$GENN")
    [ -n "$DUTC" ] && [ -n "$GENC" ] && break
    sleep 30
done
case "$DUTC $GENC" in
172.16.*" "172.16.*) ;;
*)
    log "refusing: no production control address, dut '$DUTC' gen '$GENC'"
    exit 1
    ;;
esac
dut() { log "dut: $*"; timeout 3600 $SSH root@"$DUTC" "$@" < /dev/null >> "$LOG" 2>&1; }
gen() { log "gen: $*"; timeout 3600 $SSH root@"$GENC" "$@" < /dev/null >> "$LOG" 2>&1; }
dutq() { $SSH root@"$DUTC" "$@" < /dev/null 2> /dev/null; }
genq() { $SSH root@"$GENC" "$@" < /dev/null 2> /dev/null; }

# test addresses, which must be the kavlan names' addresses on ens1f0np0 and never production ones
DUTIP=$(dutq "ip -4 -j addr show $IF | jq -r '.[0].addr_info[0].local'")
GENIP=$(genq "ip -4 -j addr show $IF | jq -r '.[0].addr_info[0].local'")
DUTMAC=$(dutq "ip -j link show $IF | jq -r '.[0].address'")
GENMAC=$(genq "ip -j link show $IF | jq -r '.[0].address'")
GENPCI=$(genq "ethtool -i $IF | awk '/bus-info/{print \$2}'")
log "dut ctl $DUTC test $DUTIP $DUTMAC, gen ctl $GENC test $GENIP $GENMAC pci $GENPCI"
for a in "$DUTIP" "$GENIP"; do
    case $a in
    10.*) ;;
    *)
        log "refusing: test address '$a' is not in the kavlan"
        exit 1
        ;;
    esac
done
[ "$(getent hosts "$DUTN-kavlan-$VLAN.louvain.grid5000.fr" | awk '{print $1}')" = "$DUTIP" ] || {
    log "refusing: $DUTIP is not $DUTN's kavlan address"
    exit 1
}
[ "$(getent hosts "$GENN-kavlan-$VLAN.louvain.grid5000.fr" | awk '{print $1}')" = "$GENIP" ] || {
    log "refusing: $GENIP is not $GENN's kavlan address"
    exit 1
}

# pktgen --srcips and testpmd's multi-flow spoof sources outside the kavlan /18. The dut answers
# them with icmp, which would leave by the production default route, so a blackhole for 10/8 drops
# those packets in the dut's loose rp_filter while the kavlan's own /18 stays the longer match.
for c in "$DUTC" "$GENC"; do
    $SSH root@"$c" "ip route replace blackhole 10.0.0.0/8" < /dev/null >> "$LOG" 2>&1
    if $SSH root@"$c" "ip route get 10.200.0.1" < /dev/null > /dev/null 2>&1; then
        log "refusing: the blackhole for 10.0.0.0/8 is not in place on $c"
        exit 1
    fi
done

gen_start() { # threads [extra gen.nu flags]
    gen "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu $W/gen.nu'; setsid nohup nu $W/gen.nu --iface $IF --dst $DUTIP --dstmac $DUTMAC --count 4000000000 --threads $1 ${2:-} > /tmp/gen.log 2>&1 < /dev/null &"
    sleep 15
    log "dut rx pps $(dutq "a=\$(cat /sys/class/net/$IF/statistics/rx_packets); sleep 3; b=\$(cat /sys/class/net/$IF/statistics/rx_packets); echo \$(( (b-a)/3 ))")"
}
gen_stop() { gen "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu $W/gen.nu'; true"; }
dutgen_start() { # threads, the dut sends to the generator through tc egress
    dut "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu $W/gen.nu'; setsid nohup nu $W/gen.nu --iface $IF --dst $GENIP --dstmac $GENMAC --count 4000000000 --threads $1 --queue-xmit > /tmp/gen.log 2>&1 < /dev/null &"
    sleep 15
    log "dut tx pps $(dutq "a=\$(cat /sys/class/net/$IF/statistics/tx_packets); sleep 3; b=\$(cat /sys/class/net/$IF/statistics/tx_packets); echo \$(( (b-a)/3 ))")"
}
dutgen_stop() { dut "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu $W/gen.nu'; true"; }
iperf_stop() { dut "pkill -x iperf3; true"; gen "pkill -x iperf3; true"; sleep 2; }
iperf_rx() { # streams [extra iperf3 client flags], generator to dut
    iperf_stop
    dut "iperf3 -s -D"
    gen "setsid nohup iperf3 -c $DUTIP -P $1 ${2:-} -t 86400 > /tmp/iperf.log 2>&1 < /dev/null &"
    sleep 10
}
iperf_tx() { # streams [extra iperf3 client flags], dut to generator
    iperf_stop
    gen "iperf3 -s -D"
    dut "setsid nohup iperf3 -c $GENIP -P $1 ${2:-} -t 86400 > /tmp/iperf.log 2>&1 < /dev/null &"
    sleep 10
}
quiet() {
    gen_stop
    dutgen_stop
    iperf_stop
    dut "pkill -KILL -f '^$PB/progbench '; sysctl -qw kernel.bpf_stats_enabled=0; ethtool -K $IF gro on tso on gso on; ethtool -L $IF combined 63; true"
}
fetch() { $SCP root@"$DUTC":'/root/res/*' "$OUT/res/" >> "$LOG" 2>&1; }
# the dut's power settings: dflt is the image's (turbo on, every C-state enabled), fixed turns turbo
# off and disables C6 and deeper, the generator keeps its own so the offered load stays the same.
# It fails when the dut reads back other settings, as one without intel_pstate or a C6 state would
power() { # dflt or fixed
    local turbo=0 deep=0 got
    [ "$1" = fixed ] && turbo=1 deep=1
    dut "echo $turbo > /sys/devices/system/cpu/intel_pstate/no_turbo; for s in /sys/devices/system/cpu/cpu*/cpuidle/state*; do case \$(cat \$s/name) in C6* | C7* | C8* | C9* | C10*) echo $deep > \$s/disable ;; *) echo 0 > \$s/disable ;; esac; done; echo no_turbo \$(cat /sys/devices/system/cpu/intel_pstate/no_turbo) disabled \$(cat /sys/devices/system/cpu/cpu*/cpuidle/state*/disable | sort | uniq -c | tr -s ' \n' ' ')"
    got=$(dutq "cat /sys/devices/system/cpu/intel_pstate/no_turbo; for s in /sys/devices/system/cpu/cpu*/cpuidle/state*; do case \$(cat \$s/name) in C6* | C7* | C8* | C9* | C10*) cat \$s/disable ;; esac; done | sort -u" | tr '\n' ' ')
    if [ "$got" != "$turbo $deep " ]; then
        log "power $1 reads back no_turbo and C6 disable '$got', want '$turbo $deep '"
        return 1
    fi
    sleep 5
}

# one measure.nu call; the variant names an rfm configuration or a monitor
m() { # phase label variant n [extra measure.nu flags]
    local ph=$1 lb=$2 v=$3 n=$4
    shift 4
    local a=$v env="" bpf=""
    case $v in
    rfm) bpf=$RFM_EXACT; env=$RFM_ENV ;;
    rfm_sampled) a=rfm; bpf=$RFM_SAMPLED; env=$RFM_ENV ;;
    rfm_default) a=rfm ;;
    rfm_n1) a=rfm; bpf=$RFM_N1; env=$RFM_ENV ;;
    rfm_acc) a=rfm; bpf=$RFM_ACC ;;
    rfm_mem) a=rfm; bpf=$RFM_MEM ;;
    netobserv_sized) a=netobserv ;;
    esac
    local args=(--iface "$IF" --agent "$a" --n "$n" --label "$lb $v" --out "/root/res/$ph.jsonl")
    [ -n "$bpf" ] && args+=(--rfm-bpf "$bpf")
    if [ "${DRY:-0}" = 1 ]; then
        # windows of a few seconds, a zero stat window stays off
        local i x=("$@")
        for ((i = 0; i < ${#x[@]} - 1; i++)); do
            case ${x[i]} in
            --warmup) x[i + 1]=3 ;;
            --secs) x[i + 1]=4 ;;
            --stat-secs) [ "${x[i + 1]}" = 0 ] || x[i + 1]=2 ;;
            esac
        done
        set -- "${x[@]}"
    fi
    args+=("$@")
    dut "timeout 900 ${env:+env $env }nu $W/measure.nu$(printf ' %q' "${args[@]}") > /dev/null 2>> /root/res/$ph.err; echo exit=\$?"
}
shuf_words() { printf '%s\n' "$@" | shuf | tr '\n' ' '; }

for ph in $PHASES; do
    log "=== phase $ph"
    case $ph in
    setup)
        for c in "$DUTC" "$GENC"; do
            $SSH root@"$c" "rm -rf $W $PB; mkdir -p /root/res" < /dev/null >> "$LOG" 2>&1
            $SCP -r "$SRC/workload" root@"$c":$W >> "$LOG" 2>&1
            $SCP -r "$SRC/progbench" root@"$c":$PB >> "$LOG" 2>&1
            $SSH root@"$c" "ethtool -G $IF rx 8192 tx 8192; for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > \$g; done; sysctl -qw kernel.bpf_stats_enabled=0; pkill -x iperf3; true" < /dev/null >> "$LOG" 2>&1
            $SSH root@"$c" "hostname; uname -a; cat /proc/cmdline; lscpu; free -g; ethtool -i $IF; ethtool -k $IF; ethtool -g $IF; ethtool -l $IF; ethtool -c $IF; cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor /sys/devices/system/cpu/intel_pstate/no_turbo; cat /sys/devices/system/cpu/cpu0/cpuidle/state*/name /sys/devices/system/cpu/cpu0/cpuidle/state*/disable; systemctl is-active irqbalance; sysctl net.core net.ipv4.conf.$IF.rp_filter net.ipv4.icmp_msgs_per_sec; ip route; rfm version; iperf3 --version; nu --version; pmacctd -V 2>&1 | head -2; softflowd -v 2>&1 | head -2; for i in \$(grep mlx5_comp /proc/interrupts | cut -d: -f1); do echo irq \$i \$(cat /proc/irq/\$i/smp_affinity_list); done" < /dev/null > "$OUT/inventory-$c.txt" 2>&1
        done
        quiet
        ;;
    b5)
        quiet
        dut "timeout 2400 nu $W/progbench.nu --dir $PB --ns '100 1000 1' --trials $TRIALS --cpu 2 > /root/res/b5-progbench.log 2>&1; cp /tmp/progbench.jsonl /root/res/b5-progbench.jsonl"
        for o in round_robin burst; do
            dut "timeout 2400 nu $W/progbench_accuracy.nu --dir $PB --flows 1000 --order $o --cpu 2 > /root/res/b5-accuracy-$o.log 2>&1; cp /tmp/progbench_accuracy_$o.jsonl /root/res/b5-accuracy-$o.jsonl"
        done
        ;;
    b1)
        for sc in rx_gro rx_nogro tx_tso tx_notso; do
            quiet
            case $sc in
            rx_gro) iperf_rx 8 ;;
            rx_nogro) dut "ethtool -K $IF gro off"; iperf_rx 8 ;;
            tx_tso) iperf_tx 8 ;;
            tx_notso) dut "ethtool -K $IF tso off gso off"; iperf_tx 8 ;;
            esac
            for r in $R3; do
                for v in $(shuf_words rfm_acc netobserv hsflowd); do
                    m b1 "$sc r$r" "$v" 100 --counts --warmup 12 --secs 45 --stat-secs 5
                done
            done
        done
        quiet
        ;;
    b3)
        for N in 1000 100 10 1; do
            gen_start 1
            for r in $R3; do
                for v in $(shuf_words none rfm rfm_sampled rfm_default netobserv hsflowd pmacctd softflowd); do
                    [ "$N" = 1 ] && [ "$v" = rfm ] && v=rfm_n1
                    m b3 "base N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                done
            done
        done
        for N in 100 10; do
            gen_start 4
            for r in $R3; do
                for v in $(shuf_words none rfm rfm_sampled netobserv hsflowd); do
                    m b3 "hi N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                done
            done
        done
        gen_start 8
        for r in $R2; do
            for v in $(shuf_words none rfm rfm_sampled netobserv hsflowd); do
                m b3 "top N100 r$r" "$v" 100 --warmup 10 --secs 30 --stat-secs 8
            done
        done
        quiet
        ;;
    b4)
        for F in 1000 5000 20000 100000 1000000; do
            case $F in
            100000) gen_start 1 "--flows 1000 --srcips 100" ;;
            1000000) gen_start 1 "--flows 1000 --srcips 1000" ;;
            *) gen_start 1 "--flows $F" ;;
            esac
            big=()
            [ "$F" -gt 60000 ] && big=(--rfm-extra "$BIG")
            for v in $(shuf_words rfm rfm_mem rfm_default netobserv netobserv_sized hsflowd); do
                case $v in
                netobserv_sized) m b4 "flows$F" "$v" 100 --neto-cache "$F" --tables --warmup 15 --secs 20 --stat-secs 0 ;;
                rfm*) m b4 "flows$F" "$v" 100 --tables --warmup 15 --secs 20 --stat-secs 0 "${big[@]}" ;;
                *) m b4 "flows$F" "$v" 100 --tables --warmup 15 --secs 20 --stat-secs 0 ;;
                esac
            done
            if [ "$F" = 1000000 ]; then
                m b4 "flows$F held" rfm_n1 1 --rfm-extra "$BIG" --warmup 15 --secs 30 --stat-secs 0
                m b4 "flows$F churn" rfm_n1 1 --warmup 15 --secs 30 --stat-secs 0
            fi
        done
        gen_start 1
        for r in $R2; do
            for ring in 4096 16384 65536 262144; do
                for N in 100 10; do
                    m b4ring "ring$ring N$N r$r" rfm_default "$N" --rfm-bpf "stage_events=32\niface_slots=1\nring_buf_size=$ring" --warmup 10 --secs 30 --stat-secs 0
                done
            done
        done
        quiet
        ;;
    b7)
        quiet
        dutgen_start 1
        for N in 100 10; do
            for r in $R3; do
                for v in $(shuf_words none rfm rfm_sampled netobserv hsflowd); do
                    m b7 "udp tx N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                done
            done
        done
        dutgen_stop
        iperf_tx 8
        for r in $R2; do
            for v in $(shuf_words none rfm netobserv hsflowd); do
                m b7 "tso tx N100 r$r" "$v" 100 --warmup 10 --secs 30 --stat-secs 8
            done
        done
        quiet
        ;;
    b2)
        # receive: the per stream rate sets how many segments GRO merges, and paced small writes
        # with nodelay leave the sender one segment at a time
        for pt in "1|" "16|" "64|-b 1G" "128|-b 100M" "128|-b 10M -N -l 1448" "128|-b 2M -N -l 1448"; do
            P=${pt%%|*}
            X=${pt#*|}
            quiet
            iperf_rx "$P" "$X"
            for r in $R2; do
                for v in $(shuf_words rfm_acc netobserv hsflowd); do
                    m b2 "rx P$P ${X:-max} r$r" "$v" 100 --counts --warmup 12 --secs 30 --stat-secs 5
                done
            done
        done
        # send: paced writes with nodelay go out one skb per write, so the write size sets how many
        # segments TSO carries, where an unpaced stream queues and coalesces them into 64 KB skbs
        for X in "-N -l 1448 -b 100M" "-N -l 8K -b 100M" "-N -l 32K -b 300M" "-N -l 64K -b 1G"; do
            quiet
            iperf_tx 8 "$X"
            for r in $R2; do
                for v in $(shuf_words rfm_acc netobserv hsflowd); do
                    m b2 "tx P8 $X r$r" "$v" 100 --counts --warmup 12 --secs 30 --stat-secs 5
                done
            done
        done
        quiet
        ;;
    b12)
        quiet
        gen_start 1 "--flows 20000 --rate 1000"
        iperf_rx 8
        for r in $R3; do
            for v in $(shuf_words rfm_acc netobserv hsflowd); do
                m b12 "mixed r$r" "$v" 100 --counts --warmup 12 --secs 45 --stat-secs 5
            done
        done
        quiet
        ;;
    b8)
        quiet
        gen_start 1
        dut "timeout 900 nu $W/progbench_insitu.nu --dir $PB --iface $IF --n 100 --rounds $ROUNDS --window $WIN --out /root/res/b8-n100.jsonl > /root/res/b8-n100.log 2>&1"
        # no n=1 pass: progbench's in situ reader never drains the rings while the flood fills them at 1 in 1
        gen_start 4
        dut "timeout 900 nu $W/progbench_insitu.nu --dir $PB --iface $IF --n 100 --rounds $ROUNDS --window $WIN --labels 'none empty agent_v1 agent_v3 skip_array_lazy_nowake sampled_skip xdp_empty xdp_skip_array' --out /root/res/b8-hi.jsonl > /root/res/b8-hi.log 2>&1"
        quiet
        ;;
    b9)
        quiet
        iperf_rx 8
        # n=1000: progbench's in situ reader stalls past about 100000 events a second, which bulk
        # tcp with gro off at n=100 exceeds
        dut "timeout 900 nu $W/progbench_offload.nu --dir $PB --iface $IF --n 1000 --rounds $ROUNDS --window $WIN > /root/res/b9.log 2>&1; cp /tmp/progbench_offload.jsonl /root/res/b9.jsonl"
        quiet
        gen_start 8
        dut "timeout 900 nu $W/progbench_insitu.nu --dir $PB --iface $IF --n 1000 --rounds $ROUNDS --window $WIN --labels 'none agent_v1 skip_array_lazy_nowake xdp_empty xdp_skip_array' --out /root/res/b9-flood.jsonl > /root/res/b9-flood.log 2>&1"
        quiet
        ;;
    b10)
        quiet
        genq "nu $W/dpdk.nu --pci $GENPCI --peer $DUTMAC --self-ip $GENIP --dst-ip $DUTIP --cores 0-16 --nb-cores 16 --txq 16 --rxq 16 --size 64" > "$OUT/res/b10-dpdk-start.txt" 2>&1
        dut "nu $W/realnic.nu --iface $IF --ns '1000 100 10' --secs $SECS --drop --bpf '$RFM_EXACT' --extra '$BIG' > /root/res/b10-realnic.log 2>&1; cp /tmp/realnic.json /root/res/b10-realnic.json"
        dut "nu $W/realnic.nu --iface $IF --ns '1' --secs $SECS --drop --bpf '$RFM_N1' --extra '$BIG' > /root/res/b10-realnic-n1.log 2>&1; cp /tmp/realnic.json /root/res/b10-realnic-n1.json"
        dut "nu $W/realnic.nu --iface $IF --ns '100 1' --secs $SECS --drop --extra '$BIG' > /root/res/b10-realnic-default.log 2>&1; cp /tmp/realnic.json /root/res/b10-realnic-default.json"
        genq "tail -5 /tmp/dpdk.log; nu $W/dpdk.nu --stop" > "$OUT/res/b10-dpdk-stop.txt" 2>&1
        gen_start 8
        dut "nu $W/rss.nu --iface $IF --queues '$QS' --ns '100' --secs $SECS --bpf '$RFM_EXACT' > /root/res/b10-rss.log 2>&1; cp /tmp/rss.json /root/res/b10-rss.json"
        dut "nu $W/rss.nu --iface $IF --queues '$QS' --ns '1' --secs $SECS --bpf '$RFM_N1' > /root/res/b10-rss-n1.log 2>&1; cp /tmp/rss.json /root/res/b10-rss-n1.json"
        quiet
        ;;
    b11)
        quiet
        gen_start 1
        for r in $R3; do
            dut "nu $W/control.nu --iface $IF --n 100 --bpf '$RFM_EXACT' --changes $CHANGES --label 'control r$r' --out /root/res/b11.jsonl > /root/res/b11-control.log 2>&1"
        done
        # adaptive against static sampling at N=1 while the generator ramps over 1, 2, 4 and 8 threads
        for r in $R2; do
            for mode in $(shuf_words adaptive static); do
                gen_start 1
                flag=""
                [ "$mode" = adaptive ] && flag=--adaptive
                dut "setsid nohup nu $W/control.nu --iface $IF --n 1 --bpf '$RFM_N1' --timeline $flag --secs $((STEP * 4)) --label 'ramp $mode r$r' --out /root/res/b11.jsonl > /root/res/b11-ramp.log 2>&1 < /dev/null &"
                for t in 2 4 8; do
                    sleep $((STEP - 18))
                    gen_start $t
                done
                for _ in $(seq 1 120); do
                    [ -z "$(dutq "pgrep -f '^nu $W/control.nu'")" ] && break
                    sleep 5
                done
                dut "pkill -f '^nu $W/control.nu'; pkill -f '^[^ ]*rfm agent'; true"
            done
        done
        quiet
        ;;
    more)
        # two more rounds of the accuracy and base cost cells, for five in all
        for sc in rx_gro tx_tso; do
            quiet
            case $sc in
            rx_gro) iperf_rx 8 ;;
            tx_tso) iperf_tx 8 ;;
            esac
            for r in 4 5; do
                for v in $(shuf_words rfm_acc netobserv hsflowd); do
                    m b1 "$sc r$r" "$v" 100 --counts --warmup 12 --secs 45 --stat-secs 5
                done
            done
        done
        for N in 100 10; do
            gen_start 1
            for r in 4 5; do
                for v in $(shuf_words none rfm rfm_sampled rfm_default netobserv hsflowd pmacctd softflowd); do
                    m b3 "base N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                done
            done
        done
        quiet
        ;;
    more2)
        # rounds four and five of the other head to head and egress cells
        for N in 1000 1; do
            gen_start 1
            for r in 4 5; do
                for v in $(shuf_words none rfm rfm_sampled rfm_default netobserv hsflowd pmacctd softflowd); do
                    [ "$N" = 1 ] && [ "$v" = rfm ] && v=rfm_n1
                    m b3 "base N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                done
            done
        done
        for N in 100 10; do
            gen_start 4
            for r in 4 5; do
                for v in $(shuf_words none rfm rfm_sampled netobserv hsflowd); do
                    m b3 "hi N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                done
            done
        done
        quiet
        dutgen_start 1
        for N in 100 10; do
            for r in 4 5; do
                for v in $(shuf_words none rfm rfm_sampled netobserv hsflowd); do
                    m b7 "udp tx N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                done
            done
        done
        quiet
        ;;
    pm)
        # the b3 cells of the eBPF monitors in pairs of power settings, alternated in each round
        for load in "1 100" "1 10" "1 1" "4 100" "4 10"; do
            read -r T N <<< "$load"
            gen_start "$T"
            for r in $R3; do
                for st in $(shuf_words dflt fixed); do
                    power "$st" || break 3
                    for v in $(shuf_words none rfm rfm_sampled netobserv); do
                        [ "$N" = 1 ] && [ "$v" = rfm ] && v=rfm_n1
                        m pm "pm $st t$T N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                    done
                done
            done
        done
        power dflt
        quiet
        ;;
    *) log "unknown phase $ph" ;;
    esac
    fetch
    log "=== phase $ph done"
done
log "campaign done"
