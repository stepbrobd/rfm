#!/usr/bin/env bash
# fourth run of job 20530, behind the control run: the pm3 cells with rfm's stage on and off (pm3s),
# the b1 receive cells with the accounting programs on and off and 8 to 64 connections (b1c) and the
# cohort mixes with more flood threads (b13p), from the harness in rfm-bench-x (rfm bfbea10, the
# weekend's objects)
# It waits while the control run (pid 1770615) or any campaign.sh of the job is alive, makes a dry
# pass, drops the phases that failed in it and starts the real pass with the rest
DUT="ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 root@172.16.208.15"
sleep 120
while kill -0 1770615 2> /dev/null || pgrep -f 'workload/campaign.sh 20530' > /dev/null; do
    sleep 60
done
grep -q 'campaign done' "$HOME/rfm-ctl/campaign.log" 2> /dev/null || echo "$(date) the control run left no campaign done"
echo "$(date) starting the dry pass"
export SRC=$HOME/rfm-bench-x
export R3="1 2 3 4 5"
ALL="pm3s b1c b13p"
d=$HOME/rfm-x-dry
DRY=1 bash "$SRC/workload/campaign.sh" 20530 "$d" setup $ALL
if ! grep -q 'campaign done' "$d/campaign.log" || grep -qE 'refusing|unknown phase' "$d/campaign.log"; then
    echo "$(date) dry pass failed, the real pass is not started"
    exit 1
fi
# a phase leaves the real pass when the dry pass shows a call of it failing, its helper failing or
# no rows
bad=$(awk '/ === phase [a-z0-9]+$/ {ph = $NF} /^exit=[1-9]/ {print ph}' "$d/campaign.log" | sort -u | tr '\n' ' ')
grep -qE 'acct (on|off) leaves' "$d/campaign.log" && bad="$bad b1c"
grep -qE 'power [a-z0-9]+ reads back' "$d/campaign.log" && bad="$bad pm3s"
for f in $ALL; do
    [ -s "$d/res/$f.jsonl" ] || bad="$bad $f"
done
keep=""
for f in $ALL; do
    case " $bad " in
    *" $f "*) echo "$(date) $f failed in the dry pass and is left out" ;;
    *) keep="$keep $f" ;;
    esac
done
if [ -z "$keep" ]; then
    echo "$(date) no phase passed the dry pass, the real pass is not started"
    exit 1
fi
# the dry rows leave the result directory of the dut before the real pass appends to the same files
$DUT 'mkdir -p /root/res-dry2 && mv /root/res/pm3s* /root/res/b1c* /root/res/b13p* /root/res-dry2/; ls /tmp/acct.saved 2> /dev/null' < /dev/null
echo "$(date) dry pass done, starting the real pass:$keep"
exec bash "$SRC/workload/campaign.sh" 20530 "$HOME/rfm-x" setup $keep
