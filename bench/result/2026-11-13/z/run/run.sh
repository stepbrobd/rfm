#!/usr/bin/env bash
# sixth run of job 20530, behind the fifth: the per packet cells with turbo and C6 off for rfm with
# its defaults and without its stage, beside the tuned rfm, netobserv and an empty window of the
# same round (pm6d), from the harness in rfm-bench-z (rfm a3e1d42, the weekend's objects)
# It waits while the fifth run (pid 1836045) or any campaign.sh of the job is alive, makes a dry
# pass, and starts the real pass only if the dry pass shows no failing call and a row of every
# variant
DUT="ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 root@172.16.208.15"
sleep 120
while kill -0 1836045 2> /dev/null || pgrep -f 'workload/campaign.sh 20530' > /dev/null; do
    sleep 60
done
grep -q 'campaign done' "$HOME/rfm-y/campaign.log" 2> /dev/null || echo "$(date) the fifth run left no campaign done"
echo "$(date) starting the dry pass"
export SRC=$HOME/rfm-bench-z
d=$HOME/rfm-z-dry
DRY=1 bash "$SRC/workload/campaign.sh" 20530 "$d" setup pm6d
if ! grep -q 'campaign done' "$d/campaign.log" || grep -qE '^exit=[1-9]|refusing|unknown phase|power [a-z0-9]+ reads back' "$d/campaign.log"; then
    echo "$(date) dry pass failed, the real pass is not started"
    exit 1
fi
for v in none rfm rfm_default rfm_nostage netobserv; do
    grep -q "r1 $v\"" "$d/res/pm6d.jsonl" 2> /dev/null || {
        echo "$(date) dry pass left no row for $v, the real pass is not started"
        exit 1
    }
done
# the dry rows leave the result directory of the dut before the real pass appends to the same file
$DUT 'mkdir -p /root/res-dry4 && mv /root/res/pm6d* /root/res-dry4/' < /dev/null
echo "$(date) dry pass clean, starting the real pass: pm6d"
exec bash "$SRC/workload/campaign.sh" 20530 "$HOME/rfm-z" setup pm6d
