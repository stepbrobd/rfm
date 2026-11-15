#!/usr/bin/env bash
# rfm campaign driver for two spirou nodes in a routed kavlan, run detached on the louvain
# frontend. It only loops over the nu harness calls (measure.nu, gen.nu, progbench*.nu, realnic.nu,
# rss.nu, dpdk.nu, percpu.nu, kprofile.nu) and the iperf3 generator, which has no harness, logs
# every remote command, and copies the json lines to <outdir> after each phase.
#
# usage: campaign.sh <job id> <outdir> [phase ...]
#   the first host of the job is the dut, the second the generator. Control goes over the
#   production port, test traffic over ens1f0np0 in the kavlan only.
# phases, in this order by default:
#   setup b5 b1 b3 b4 b7 b2 b12 b8 b9 b10 b11 more more2
# and pm, the B3 cells with the dut at its default power settings and with turbo and C6 off, pm6,
# the base cells of all six monitors with them off, pm6d, the same cells for rfm with its defaults
# and without its stage, and
# sparse, the B3 cells at N of 10000 and 100000 and the B1 ones at 10000, each named on its own
# and the controls b1c, the B1 receive cells with systemd's accounting programs on and off the
# socket path and with 8 to 64 connections, b9s, the B9 bulk windows with the run time statistics on
# and off, b13s, the top cohort mix with netobserv's table enlarged, b13p, the cohort mixes past it
# with more flood threads, pm3s, the pm3 cells with rfm's stage on and off, b8s, the flood windows
# of the XDP comparison with the statistics on and off, b9p, a kernel profile of its bulk windows,
# b9m, those windows at two MTUs of the dut with nothing and with an empty XDP program attached,
# ramp, the adaptive against static half of b11 alone, and env, a record of the nodes for the
# archive
# SRC names a directory on the frontend that holds workload/ and progbench/. DRY=1 runs every
# phase with one round and windows of a few seconds, to check the commands before a night.
set -u

JOB=$1
OUT=$2
shift 2
PHASES=${*:-"setup b5 b1 b3 b4 b7 b2 b12 b8 b9 b10 b11 more more2"}
# the site and its nodes from the environment, spirou at louvain by default, with the test port,
# the production port for control (empty on a single port node such as dahu, where control rides
# the kavlan names), the channel count and the ring size (empty leaves the NIC's own)
SITE=${SITE:-louvain}
IF=${IF:-ens1f0np0}
CTL_IF=${CTL_IF-ens1f1np1}
CH=${CH-63}
RING=${RING-8192}
IMG=${IMG:-$HOME/g5k-image}
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
# the favorable configuration less its stage, so one ring record per event and no flush timer
RFM_NOSTAGE=${RFM_NOSTAGE:-'iface_slots=1\nring_buf_size=16384'}
RFM_ENV=${RFM_ENV:-''}
BIG='[agent.collector]\nmax_flows=2097152'

# rounds, R3 and R2 of most phases, RB4 of the memory points, and the monitors of the accuracy
# phases b1, b2 and b12, where pmacctd and softflowd can join, all taken from the environment
R5=${R5:-"1 2 3 4 5"}
R3=${R3:-"1 2 3"}
R2=${R2:-"1 2"}
RB4=${RB4:-1}
ACC=${ACC:-"rfm_acc netobserv hsflowd"}
TRIALS=7
ROUNDS=${ROUNDS:-3}
WIN=20s
SECS=20
QS='1 2 4 8 16 32 63'
CHANGES=12
STEP=40
if [ "${DRY:-0}" = 1 ]; then
    R5=1
    R3=1
    R2=1
    RB4=1
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
    OAR_JOB_ID=$JOB kadeploy3 -a "$IMG"/nixos-x86_64-linux.yaml -f "$OUT/nodes" --vlan "$VLAN" >> "$LOG" 2>&1 || {
        log "deploy retry failed"
        exit 1
    }
fi
DUTN=$(echo "$HOSTS" | awk '{print $1}' | cut -d. -f1)
GENN=$(echo "$HOSTS" | awk '{print $2}' | cut -d. -f1)
log "job $JOB vlan $VLAN dut $DUTN gen $GENN phases: $PHASES"
log "rounds R5 '$R5' R3 '$R3' R2 '$R2' RB4 '$RB4' accuracy monitors '$ACC'"

# the production address of a node for control, read through its kavlan name
prod() { $SSH root@"$1"-kavlan-"$VLAN".$SITE.grid5000.fr "ip -4 -j addr show $CTL_IF | jq -r '.[0].addr_info[0].local'" < /dev/null 2> /dev/null; }
DUTC=""
GENC=""
for _ in $(seq 1 20); do
    [ -z "$CTL_IF" ] && break
    DUTC=$(prod "$DUTN")
    GENC=$(prod "$GENN")
    [ -n "$DUTC" ] && [ -n "$GENC" ] && break
    sleep 30
done
if [ -z "$CTL_IF" ]; then
    # on a one port node the kavlan names carry control as well as the test traffic
    DUTC=$DUTN-kavlan-$VLAN.$SITE.grid5000.fr
    GENC=$GENN-kavlan-$VLAN.$SITE.grid5000.fr
else
    case "$DUTC $GENC" in
    172.16.*" "172.16.*) ;;
    *)
        log "refusing: no production control address, dut '$DUTC' gen '$GENC'"
        exit 1
        ;;
    esac
fi
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
[ "$(getent hosts "$DUTN-kavlan-$VLAN.$SITE.grid5000.fr" | awk '{print $1}')" = "$DUTIP" ] || {
    log "refusing: $DUTIP is not $DUTN's kavlan address"
    exit 1
}
[ "$(getent hosts "$GENN-kavlan-$VLAN.$SITE.grid5000.fr" | awk '{print $1}')" = "$GENIP" ] || {
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

# pktgen runs until stopped with count 0, since 4e9 packets a thread ran out after 25 minutes at
# 2.65 Mpps, inside the fifth round of a cell with seven monitors
gen_start() { # threads [extra gen.nu flags]
    gen "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu $W/gen.nu'; setsid nohup nu $W/gen.nu --iface $IF --dst $DUTIP --dstmac $DUTMAC --count 0 --threads $1 ${2:-} > /tmp/gen.log 2>&1 < /dev/null &"
    sleep 15
    log "dut rx pps $(dutq "a=\$(cat /sys/class/net/$IF/statistics/rx_packets); sleep 3; b=\$(cat /sys/class/net/$IF/statistics/rx_packets); echo \$(( (b-a)/3 ))")"
}
gen_stop() { gen "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu $W/gen.nu'; true"; }
dutgen_start() { # threads, the dut sends to the generator through tc egress
    dut "echo stop > /proc/net/pktgen/pgctrl; pkill -f '^nu $W/gen.nu'; setsid nohup nu $W/gen.nu --iface $IF --dst $GENIP --dstmac $GENMAC --count 0 --threads $1 --queue-xmit > /tmp/gen.log 2>&1 < /dev/null &"
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
    dut "pkill -KILL -f '^$PB/progbench '; sysctl -qw kernel.bpf_stats_enabled=0; ethtool -K $IF gro on tso on gso on; ${CH:+ethtool -L $IF combined $CH;} true"
}
fetch() { $SCP root@"$DUTC":'/root/res/*' "$OUT/res/" >> "$LOG" 2>&1; }
# the dut's power settings: dflt is the image's (turbo on, every C-state enabled), fixed turns turbo
# off and disables C6 and deeper, the generator keeps its own so the offered load stays the same.
# It fails when the dut reads back other settings, as one without intel_pstate or a C6 state would
power() { # dflt or fixed
    local turbo=0 deep=0 got
    case $1 in
    fixed) turbo=1 deep=1 ;;
    noturbo) turbo=1 ;;
    noc6) deep=1 ;;
    esac
    dut "echo $turbo > /sys/devices/system/cpu/intel_pstate/no_turbo; for s in /sys/devices/system/cpu/cpu*/cpuidle/state*; do case \$(cat \$s/name) in C6* | C7* | C8* | C9* | C10*) echo $deep > \$s/disable ;; *) echo 0 > \$s/disable ;; esac; done; echo no_turbo \$(cat /sys/devices/system/cpu/intel_pstate/no_turbo) disabled \$(cat /sys/devices/system/cpu/cpu*/cpuidle/state*/disable | sort | uniq -c | tr -s ' \n' ' ')"
    got=$(dutq "cat /sys/devices/system/cpu/intel_pstate/no_turbo; for s in /sys/devices/system/cpu/cpu*/cpuidle/state*; do case \$(cat \$s/name) in C6* | C7* | C8* | C9* | C10*) cat \$s/disable ;; esac; done | sort -u" | tr '\n' ' ')
    if [ "$got" != "$turbo $deep " ]; then
        log "power $1 reads back no_turbo and C6 disable '$got', want '$turbo $deep '"
        return 1
    fi
    sleep 5
}

# microseconds every idle state has been resident, summed over the dut's CPUs, and the time read
cstates() {
    dutq "date +%s.%N; for s in /sys/devices/system/cpu/cpu0/cpuidle/state*; do echo \$(cat \$s/name)=\$(cat /sys/devices/system/cpu/cpu*/cpuidle/\${s##*/}/time | awk '{t+=\$1} END{print t}'); done" | tr '\n' ' '
}

# what woke the dut's CPUs since boot, summed over them, as the softirqs of the hrtimer and timer
# vectors, where a bpf timer runs, and the local timer, rescheduling and function call interrupts
wakes() {
    dutq "awk '\$1 ~ /^(HRTIMER|TIMER):\$/ {s = 0; for (i = 2; i <= NF; i++) s += \$i; sub(\":\", \"\", \$1); printf \"%s=%.0f \", \$1, s}' /proc/softirqs; awk '\$1 ~ /^(LOC|RES|CAL):\$/ {s = 0; for (i = 2; i <= NF; i++) if (\$i ~ /^[0-9]+\$/) s += \$i; sub(\":\", \"\", \$1); printf \"%s=%.0f \", \$1, s}' /proc/interrupts"
}

# systemd's IP accounting programs (sd_fw_ingress and sd_fw_egress, DefaultIPAccounting on the
# image) run once per cgroup level for every skb of a socket, four levels for a process started
# over ssh
# off detaches them from the cgroup of the dut's iperf3 and from its ancestors and fails unless
# none is left on that path, on puts back what off took and fails unless each one is attached
# again, less those of a cgroup that is gone
# an iperf3 restart moves the server to a new cgroup, so on comes before it
acct() { # off or on
    local got path
    case $1 in
    off)
        # the list of what was taken only grows until an on has put all of it back
        dut "p=\$(pgrep -x iperf3 | head -1); [ -n \"\$p\" ] || exit 1; cg=/sys/fs/cgroup\$(cut -d: -f3 /proc/\$p/cgroup); echo \$cg > /tmp/acct.cg; while :; do bpftool -j cgroup show \$cg | jq -r '.[] | select((.name // \"\") | startswith(\"sd_fw_\")) | \"\(.id) \(.attach_type)\"' | while read -r id ty; do bpftool cgroup detach \$cg \$ty id \$id && echo \$cg \$ty \$id >> /tmp/acct.saved; done; [ \$cg = /sys/fs/cgroup ] && break; cg=\$(dirname \$cg); done; cat /tmp/acct.saved 2> /dev/null; true" || {
            log "acct off leaves the path unknown, no iperf3 on the dut"
            return 1
        }
        ;;
    on)
        # nothing to put back unless an off came before
        [ "$(dutq "cat /tmp/acct.saved 2> /dev/null | wc -l")" = 0 ] && return 0
        dut "while read -r cg ty id; do [ -d \$cg ] && bpftool cgroup attach \$cg \$ty id \$id multi; done < /tmp/acct.saved"
        ;;
    *) return 1 ;;
    esac
    # the programs on the path, where bpftool prints nothing for a cgroup without any
    path=$(dutq "cg=\$(cat /tmp/acct.cg); n=0; while :; do n=\$((n + \$(bpftool -j cgroup show \$cg | jq -s '[.[][] | select((.name // \"\") | startswith(\"sd_fw_\"))] | length'))); [ \$cg = /sys/fs/cgroup ] && break; cg=\$(dirname \$cg); done; echo \$n")
    got=$path
    if [ "$1" = on ]; then
        # and the ones that off took and that are still off their cgroup
        got=$(dutq "n=0; while read -r cg ty id; do [ -d \$cg ] || continue; bpftool -j cgroup show \$cg | jq -s -e --argjson id \$id 'any(.[][]; .id == \$id)' > /dev/null || n=\$((n + 1)); done < /tmp/acct.saved; echo \$n")
    fi
    if [ "$got" != 0 ]; then
        log "acct $1 leaves '$got' accounting programs in the wrong place, '$path' on the iperf3 path"
        return 1
    fi
    [ "$1" = on ] && dutq "rm -f /tmp/acct.saved"
    log "acct $1: $path accounting programs on the iperf3 path"
}

# adaptive against static sampling at N=1 while the generator ramps over 1, 2, 4 and 8 threads
ramps() { # result file
    local r mode flag t
    for r in $R2; do
        for mode in $(shuf_words adaptive static); do
            gen_start 1
            flag=""
            [ "$mode" = adaptive ] && flag=--adaptive
            dut "setsid nohup nu $W/control.nu --iface $IF --n 1 --bpf '$RFM_N1' --timeline $flag --secs $((STEP * 4)) --label 'ramp $mode r$r' --out /root/res/$1.jsonl > /root/res/$1-ramp.log 2>&1 < /dev/null &"
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
    rfm_nostage) a=rfm; bpf=$RFM_NOSTAGE; env=$RFM_ENV ;;
    netobserv_sized) a=netobserv ;;
    esac
    # rfm refuses a rate above max_sample_rate, 1000 unless set
    if [ "$a" = rfm ] && [ "$n" -gt 1000 ]; then
        bpf="${bpf:+$bpf\n}max_sample_rate=$n"
    fi
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
            $SSH root@"$c" "${RING:+ethtool -G $IF rx $RING tx $RING;} for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > \$g; done; sysctl -qw kernel.bpf_stats_enabled=0; pkill -x iperf3; true" < /dev/null >> "$LOG" 2>&1
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
                for v in $(shuf_words $ACC); do
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
            for r in $RB4; do
                lb="flows$F"
                [ "$RB4" = 1 ] || lb="flows$F r$r"
                for v in $(shuf_words rfm rfm_mem rfm_default netobserv netobserv_sized hsflowd); do
                    case $v in
                    netobserv_sized) m b4 "$lb" "$v" 100 --neto-cache "$F" --tables --warmup 15 --secs 20 --stat-secs 0 ;;
                    rfm*) m b4 "$lb" "$v" 100 --tables --warmup 15 --secs 20 --stat-secs 0 "${big[@]}" ;;
                    *) m b4 "$lb" "$v" 100 --tables --warmup 15 --secs 20 --stat-secs 0 ;;
                    esac
                done
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
                for v in $(shuf_words $ACC); do
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
                for v in $(shuf_words $ACC); do
                    m b2 "tx P8 $X r$r" "$v" 100 --counts --warmup 12 --secs 30 --stat-secs 5
                done
            done
        done
        quiet
        ;;
    b13)
        # two cohorts on one link, 8 bulk TCP connections that GRO merges and a paced flood of small
        # UDP packets that it leaves alone, the flood swept so the true packet share of each moves
        # the port counts the total and the stack's UDP counters the flood per packet (nic.udp_in),
        # and --counts splits what each monitor reports by protocol
        quiet
        iperf_rx 8
        for R in ${B13_RATES:-100 300 1000 3000}; do
            gen_start 1 "--flows 20000 --rate $R"
            for r in $R3; do
                for v in $(shuf_words $ACC); do
                    m b13 "cohort u$R r$r" "$v" 100 --counts --warmup 12 --secs 45 --stat-secs 5
                done
            done
        done
        quiet
        ;;
    pm3)
        # the pm cells with turbo and the deep idle states switched one at a time, and the idle
        # time of every state summed over the CPUs logged around each window
        for load in "1 100" "1 10"; do
            read -r T N <<< "$load"
            gen_start "$T"
            for r in $R3; do
                for st in $(shuf_words dflt fixed noturbo noc6); do
                    power "$st" || break 3
                    for v in $(shuf_words none rfm netobserv hsflowd); do
                        log "cstate pm3 $st t$T N$N r$r $v before: $(cstates)"
                        m pm3 "pm3 $st t$T N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                        log "cstate pm3 $st t$T N$N r$r $v after: $(cstates)"
                    done
                done
            done
        done
        power dflt
        quiet
        ;;
    b12)
        quiet
        gen_start 1 "--flows 20000 --rate 1000"
        iperf_rx 8
        for r in $R3; do
            for v in $(shuf_words $ACC); do
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
        ramps b11
        quiet
        ;;
    ramp)
        quiet
        ramps ramp
        quiet
        ;;
    b1c)
        # the b1 receive cells with and without the accounting programs, which run four times per
        # skb and so per packet with GRO off, with no monitor and at the 8 connections of b1 with
        # rfm as well
        # more connections tell a receiver that GRO off slows from one that the link bounds
        for P in ${B1C_P:-8 16 32 64}; do
            for sc in rx_gro rx_nogro; do
                quiet
                [ "$sc" = rx_nogro ] && dut "ethtool -K $IF gro off"
                iperf_rx "$P"
                for r in $R3; do
                    for st in $(shuf_words on off); do
                        if [ "$st" = off ]; then
                            acct off || break 4
                        fi
                        m b1c "$sc P$P acct_$st r$r" none 100 --warmup 12 --secs 45 --stat-secs 0
                        if [ "$P" = 8 ]; then
                            m b1c "$sc P$P acct_$st r$r" rfm_acc 100 --counts --warmup 12 --secs 45 --stat-secs 5
                        fi
                        if [ "$st" = off ]; then
                            acct on || break 4
                        fi
                    done
                done
            done
        done
        acct on
        quiet
        ;;
    b9s)
        # the b9 bulk windows with the run time statistics on and off and with nothing attached,
        # since the statistics add two clock reads to every program run and XDP runs once per
        # packet, with GRO on the programs that do nothing run as well, which splits the cost of
        # a hook from the cost of the program on it, and each GRO setting is a call of its own
        # PWR names the power settings of the dut for the phase and its result files
        # a run with GRO off has taken three times its 23 s of warm-up and window, as it does
        # when a flow keeps the CPU busy that progbench pins itself to, and the timeouts allow
        # for it
        power "${PWR:-dflt}" || continue
        quiet
        iperf_rx 8
        f=/root/res/b9s${PWR:+-$PWR}
        dut "rm -f /tmp/progbench_offload.jsonl; timeout 3300 nu $W/progbench_offload.nu --dir $PB --iface $IF --n 1000 --rounds $ROUNDS --window $WIN --gro on --labels 'none empty skip_array_lazy_nowake xdp_empty xdp_skip_array' --stats 'on off' > $f.log 2>&1; cp /tmp/progbench_offload.jsonl $f.jsonl"
        dut "rm -f /tmp/progbench_offload.jsonl; timeout 3300 nu $W/progbench_offload.nu --dir $PB --iface $IF --n 1000 --rounds $ROUNDS --window $WIN --gro off --labels 'none skip_array_lazy_nowake xdp_skip_array' --stats 'on off' >> $f.log 2>&1; cat /tmp/progbench_offload.jsonl >> $f.jsonl"
        power dflt
        quiet
        ;;
    b13s)
        # the top cohort mix with netobserv's flow table enlarged past the 20000 flows of the flood,
        # which separates the samples its default table of 5000 drops from the skb unit
        quiet
        iperf_rx 8
        gen_start 1 "--flows 20000 --rate 1000"
        for r in $R3; do
            for v in $(shuf_words netobserv netobserv_sized hsflowd); do
                case $v in
                netobserv_sized) m b13s "cohort u1000 r$r" "$v" 100 --neto-cache 65536 --counts --warmup 12 --secs 45 --stat-secs 5 ;;
                *) m b13s "cohort u1000 r$r" "$v" 100 --counts --warmup 12 --secs 45 --stat-secs 5 ;;
                esac
            done
        done
        quiet
        ;;
    b8s)
        # the flood windows of the XDP comparison with the run time statistics off and on, since
        # busy cores need none and the statistics add two clock reads to every program run
        # n=1000 at 8 threads, where the in situ reader stalls at 1 in 100
        # PWR names the power settings of the dut for the phase and its result files
        power "${PWR:-dflt}" || continue
        for T in 1 4 8; do
            quiet
            gen_start "$T"
            n=100
            [ "$T" = 8 ] && n=1000
            dut "timeout 3300 nu $W/progbench_insitu.nu --dir $PB --iface $IF --n $n --rounds $ROUNDS --window $WIN --stats 'off on' --labels 'none empty skip_array_lazy_nowake xdp_empty xdp_skip_array' --out /root/res/b8s${PWR:+-$PWR}-t$T.jsonl > /root/res/b8s${PWR:+-$PWR}-t$T.log 2>&1"
        done
        power dflt
        quiet
        ;;
    b9p)
        # where the busy cores of the bulk TCP windows go, as a kernel profile by function with
        # nothing attached, with the exact profile at TCX and at XDP and with an XDP program
        # that does nothing, statistics off
        power "${PWR:-dflt}" || continue
        quiet
        iperf_rx 8
        # kprofile.nu lifts the limits of the kernel on sampling for a profile and puts them back,
        # and they are put back here once more in case a profile was cut short
        lim=$(dutq "sysctl -n kernel.perf_event_max_sample_rate kernel.perf_cpu_time_max_percent" | tr '\n' ' ')
        for l in none skip_array_lazy_nowake xdp_empty xdp_skip_array; do
            dut "timeout 600 nu $W/kprofile.nu --dir $PB --iface $IF --label $l --secs $SECS --out /root/res/b9p${PWR:+-$PWR}-$l > /root/res/b9p${PWR:+-$PWR}-$l.log 2>&1; echo exit=\$?"
        done
        read -r rate pct <<< "$lim"
        if [ -n "$pct" ]; then
            dut "sysctl -qw kernel.perf_cpu_time_max_percent=25; sysctl -qw kernel.perf_event_max_sample_rate=$rate; sysctl -qw kernel.perf_cpu_time_max_percent=$pct; sysctl kernel.perf_event_max_sample_rate kernel.perf_cpu_time_max_percent"
        fi
        power dflt
        quiet
        ;;
    b9m)
        # the bulk TCP windows with nothing attached and with an XDP program that does nothing,
        # at the dut's own MTU and at 1700
        # mlx5 sizes a receive buffer from the MTU and the headroom, and at 1500 the headroom of
        # XDP takes it past half a page, so every frame gets a page of its own where two shared one
        # an MTU of 1700 on the dut alone does the same with nothing attached while the frames on
        # the wire stay those of the generator's 1500, which splits the cost of that buffer layout
        # from the cost of the hook
        # the MTUs alternate within a round in a shuffled order and iperf3 restarts after each
        # change, since the driver reopens its channels
        # the dut's MTU is put back at the end and read back
        power "${PWR:-dflt}" || continue
        quiet
        mtu0=$(dutq "cat /sys/class/net/$IF/mtu")
        case $mtu0 in
        '' | *[!0-9]*)
            log "refusing: no MTU read from the dut"
            power dflt
            continue
            ;;
        esac
        f=/root/res/b9m${PWR:+-$PWR}
        for r in $(seq 1 "$ROUNDS"); do
            for mtu in $(shuf_words "$mtu0" 1700); do
                dut "ip link set dev $IF mtu $mtu; sleep 3; echo round $r mtu \$(cat /sys/class/net/$IF/mtu)"
                iperf_rx 8
                dut "rm -f /tmp/progbench_offload.jsonl; timeout 600 nu $W/progbench_offload.nu --dir $PB --iface $IF --n 1000 --rounds 1 --window $WIN --gro on --labels 'none xdp_empty' --stats off >> $f.log 2>&1; cat /tmp/progbench_offload.jsonl >> $f-mtu$mtu.jsonl"
            done
        done
        quiet
        dut "ip link set dev $IF mtu $mtu0; sleep 3; echo mtu \$(cat /sys/class/net/$IF/mtu)"
        [ "$(dutq "cat /sys/class/net/$IF/mtu")" = "$mtu0" ] || log "refusing: the dut's MTU does not read back $mtu0"
        power dflt
        ;;
    env)
        # what the inventory of setup leaves out, for the archive: the idle states with their
        # latencies, the link and its receive hash, the builds of the tools and every loaded program
        for c in "$DUTC" "$GENC"; do
            $SSH root@"$c" "hostname; date -u +%FT%TZ; cat /etc/os-release | head -5; systemctl --version | head -1; systemctl show -p DefaultIPAccounting; cat /sys/devices/system/cpu/cpuidle/current_driver /sys/devices/system/cpu/cpuidle/current_governor /sys/devices/system/cpu/intel_pstate/status; for s in /sys/devices/system/cpu/cpu0/cpuidle/state*; do echo \$(cat \$s/name) latency \$(cat \$s/latency) residency \$(cat \$s/residency) disable \$(cat \$s/disable); done; cat /sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference /sys/kernel/mm/transparent_hugepage/enabled /proc/sys/kernel/numa_balancing; cat /sys/kernel/debug/sched/preempt; ethtool $IF; ethtool --show-fec $IF; ethtool -x $IF | head -24; ethtool -n $IF rx-flow-hash udp4; ethtool -n $IF rx-flow-hash tcp4; ethtool --show-priv-flags $IF; cat /sys/class/net/$IF/device/numa_node; ip -d link show $IF; tc qdisc show dev $IF | head -3; sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.core.default_qdisc net.core.bpf_jit_enable net.core.bpf_jit_harden kernel.bpf_stats_enabled; bpftool version; bpftool prog show; for b in rfm netobserv-ebpf-agent hsflowd pmacctd softflowd iperf3 nu bpftool ethtool; do echo \$b \$(command -v \$b | xargs -r readlink -f); done; dmidecode -t bios -t system | grep -E 'Vendor|Version|Release Date|Manufacturer|Product Name'" < /dev/null > "$OUT/env-$c.txt" 2>&1
        done
        ;;
    b13p)
        # the cohort mixes past the share one pktgen thread reaches beside bulk TCP, with 2, 4 and
        # 8 flood threads at full rate, then 8 with the TCP side paced to a fifth of the link, and
        # netobserv at its default table as well as at one sized past the flood's flows
        for mix in "2|" "4|" "8|" "8|--fq-rate 2.5G"; do
            T=${mix%%|*}
            X=${mix#*|}
            quiet
            iperf_rx 8 "$X"
            gen_start "$T" "--flows 20000"
            for r in $R3; do
                for v in $(shuf_words rfm_acc netobserv netobserv_sized hsflowd); do
                    case $v in
                    netobserv_sized) m b13p "cohort t$T${X:+p} r$r" "$v" 100 --neto-cache 65536 --counts --warmup 12 --secs 45 --stat-secs 5 ;;
                    *) m b13p "cohort t$T${X:+p} r$r" "$v" 100 --counts --warmup 12 --secs 45 --stat-secs 5 ;;
                    esac
                done
            done
        done
        quiet
        ;;
    pm3s)
        # the pm3 cells at default power and with C6 off, with rfm's stage on and off, since only
        # the stage arms a timer on each CPU, and what woke the CPUs beside their idle time, summed
        # in the log and per CPU in pm3s-cpu.jsonl
        gen_start 1
        for r in $R3; do
            for st in $(shuf_words dflt noc6); do
                power "$st" || break 2
                for v in $(shuf_words none rfm rfm_nostage netobserv); do
                    dut "nu $W/percpu.nu --label 'pm3s $st t1 N100 r$r $v before' --out /root/res/pm3s-cpu.jsonl"
                    log "cstate pm3s $st t1 N100 r$r $v before: $(cstates)$(wakes)"
                    m pm3s "pm3s $st t1 N100 r$r" "$v" 100 --warmup 10 --secs 30 --stat-secs 8
                    log "cstate pm3s $st t1 N100 r$r $v after: $(cstates)$(wakes)"
                    dut "nu $W/percpu.nu --label 'pm3s $st t1 N100 r$r $v after' --out /root/res/pm3s-cpu.jsonl"
                done
            done
        done
        power dflt
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
        # the iperf3 stream of the last accuracy cell stops before the pktgen ones
        quiet
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
                    for v in $(shuf_words none rfm rfm_sampled netobserv hsflowd); do
                        [ "$N" = 1 ] && [ "$v" = rfm ] && v=rfm_n1
                        m pm "pm $st t$T N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                    done
                done
            done
        done
        power dflt
        quiet
        ;;
    pm6)
        # the b3 base cells of all six monitors with turbo and C6 off, so the busy cores of the
        # libpcap monitors and hsflowd compare with the fixed cells of pm
        # N of 1000 comes last, a walltime that cuts the phase short then costs the cell pm never had
        power fixed || continue
        for N in 100 10 1 1000; do
            gen_start 1
            for r in $R5; do
                for v in $(shuf_words none rfm rfm_sampled netobserv hsflowd pmacctd softflowd); do
                    [ "$N" = 1 ] && [ "$v" = rfm ] && v=rfm_n1
                    m pm6 "pm fixed t1 N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                done
            done
        done
        power dflt
        quiet
        ;;
    pm6d)
        # the pm6 cells for the two rfm configurations pm6 left out, the defaults and the tuned one
        # without its stage, beside the tuned one, netobserv and an empty window of the same
        # round, so the per packet times of every configuration exist with turbo and C6 off
        power fixed || continue
        for N in 100 10 1000; do
            gen_start 1
            for r in $R5; do
                for v in $(shuf_words none rfm rfm_default rfm_nostage netobserv); do
                    m pm6d "pm fixed t1 N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                done
            done
        done
        power dflt
        quiet
        ;;
    b4cov)
        # flow coverage as the distinct flows netobserv writes to its flow log over the window, at its
        # default table and with the table sized to the offered flows, and the flows rfm holds
        for F in 1000 5000 20000 100000 1000000; do
            case $F in
            100000) gen_start 1 "--flows 1000 --srcips 100" ;;
            1000000) gen_start 1 "--flows 1000 --srcips 1000" ;;
            *) gen_start 1 "--flows $F" ;;
            esac
            big=()
            [ "$F" -gt 60000 ] && big=(--rfm-extra "$BIG")
            for r in $R3; do
                for v in $(shuf_words rfm netobserv netobserv_sized); do
                    case $v in
                    netobserv_sized) m b4cov "flows$F r$r" "$v" 100 --neto-cache "$F" --flows-seen --tables --warmup 15 --secs 30 --stat-secs 0 ;;
                    netobserv) m b4cov "flows$F r$r" "$v" 100 --flows-seen --tables --warmup 15 --secs 30 --stat-secs 0 ;;
                    *) m b4cov "flows$F r$r" "$v" 100 --tables --warmup 15 --secs 30 --stat-secs 0 "${big[@]}" ;;
                    esac
                done
            done
        done
        quiet
        ;;
    sparse)
        # sparse sampling as on fast links: the b3 cost cells at N of 10000 and 100000 and the b1
        # accuracy cells at 10000
        for load in "1 10000" "4 10000" "1 100000"; do
            read -r T N <<< "$load"
            cell=base
            [ "$T" = 4 ] && cell=hi
            gen_start "$T"
            for r in $R3; do
                for v in $(shuf_words none rfm rfm_sampled netobserv hsflowd); do
                    m b3 "$cell N$N r$r" "$v" "$N" --warmup 10 --secs 30 --stat-secs 8
                done
            done
        done
        for sc in rx_gro tx_tso; do
            quiet
            case $sc in
            rx_gro) iperf_rx 8 ;;
            tx_tso) iperf_tx 8 ;;
            esac
            for r in $R3; do
                for v in $(shuf_words rfm_acc netobserv hsflowd); do
                    m b1 "$sc N10000 r$r" "$v" 10000 --counts --warmup 12 --secs 45 --stat-secs 5
                done
            done
        done
        quiet
        ;;
    *) log "unknown phase $ph" ;;
    esac
    fetch
    log "=== phase $ph done"
done
log "campaign done"
