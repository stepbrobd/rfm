#!/usr/bin/env bash
# fifth run of job 20530, behind the fourth: the flood windows (b8s) and the bulk TCP windows (b9s)
# of the XDP comparison with the run time statistics off and on and the power settings of the dut
# fixed, a kernel profile of the bulk windows (b9p) and a record of both nodes (env), from the
# harness in rfm-bench-y (the weekend's objects)
# It waits while the fourth run (pid 1787765) or any campaign.sh of the job is alive, makes a dry
# pass, drops the phases that failed in it and starts the real pass with the rest
DUT="ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 root@172.16.208.15"
sleep 120
while kill -0 1787765 2> /dev/null || pgrep -f 'workload/campaign.sh 20530' > /dev/null; do
    sleep 60
done
grep -q 'campaign done' "$HOME/rfm-x/campaign.log" 2> /dev/null || echo "$(date) the fourth run left no campaign done"
echo "$(date) starting the dry pass"
export SRC=$HOME/rfm-bench-y
export ROUNDS=5 PWR=fixed
ALL="b8s b9s b9p"
d=$HOME/rfm-y-dry
DRY=1 bash "$SRC/workload/campaign.sh" 20530 "$d" setup $ALL
if ! grep -q 'campaign done' "$d/campaign.log" || grep -qE 'refusing|unknown phase' "$d/campaign.log"; then
    echo "$(date) dry pass failed, the real pass is not started"
    exit 1
fi
# a phase leaves the real pass when the dry pass shows a call of it failing, the power helper
# failing or rows missing
bad=$(awk '/ === phase [a-z0-9]+$/ {ph = $NF} /^exit=[1-9]/ {print ph}' "$d/campaign.log" | sort -u | tr '\n' ' ')
grep -qE 'power [a-z0-9]+ reads back' "$d/campaign.log" && bad="$bad b8s b9s b9p"
[ -s "$d/res/b8s-fixed-t1.jsonl" ] && [ -s "$d/res/b8s-fixed-t4.jsonl" ] && [ -s "$d/res/b8s-fixed-t8.jsonl" ] || bad="$bad b8s"
grep -q 'xdp_empty gro=on' "$d/res/b9s-fixed.jsonl" 2> /dev/null && grep -q 'xdp_skip_array gro=off' "$d/res/b9s-fixed.jsonl" || bad="$bad b9s"
for l in none skip_array_lazy_nowake xdp_empty xdp_skip_array; do
    [ -s "$d/res/b9p-fixed-$l.json" ] && grep -q '^@k\[' "$d/res/b9p-fixed-$l.txt" 2> /dev/null || bad="$bad b9p"
done
keep=""
for f in $ALL; do
    case " $bad " in
    *" $f "*) echo "$(date) $f failed in the dry pass and is left out" ;;
    *) keep="$keep $f" ;;
    esac
done
# the dry rows leave the result directory of the dut, and the record of the nodes needs no dry pass
$DUT 'mkdir -p /root/res-dry3 && mv /root/res/b8s-fixed* /root/res/b9s-fixed* /root/res/b9p-fixed* /root/res-dry3/' < /dev/null
echo "$(date) dry pass done, starting the real pass:$keep env"
exec bash "$SRC/workload/campaign.sh" 20530 "$HOME/rfm-y" setup $keep env
