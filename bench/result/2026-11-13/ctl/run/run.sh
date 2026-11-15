#!/usr/bin/env bash
# control run of job 20530, after its three drivers: the b1 receive cells with systemd's accounting
# programs on and off the socket path (b1c), the b9 bulk windows with the run time statistics on and
# off (b9s), the top cohort mix with netobserv's table enlarged (b13s) and the ramp with a timestamp
# per read (ramp), from the harness in rfm-bench-ctl (rfm 89a7718, the weekend's objects)
# It waits while the third driver's wrapper (pid 1184962) or any campaign.sh of the job is alive,
# makes a dry pass, and starts the real pass only if the dry pass logged no failure
DUT="ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 root@172.16.208.15"
sleep 120
while kill -0 1184962 2> /dev/null || pgrep -f 'workload/campaign.sh 20530' > /dev/null; do
    sleep 60
done
grep -q 'campaign done' "$HOME/rfm-weekend3/campaign.log" 2> /dev/null || echo "$(date) third driver left no campaign done"
echo "$(date) starting the dry pass"
export SRC=$HOME/rfm-bench-ctl
export R3="1 2 3 4 5" R2="1 2 3 4 5" ROUNDS=5
PH="setup b1c b9s b13s ramp"
DRY=1 bash "$SRC/workload/campaign.sh" 20530 "$HOME/rfm-ctl-dry" $PH
d=$HOME/rfm-ctl-dry
if ! grep -q 'campaign done' "$d/campaign.log" || grep -qE '^exit=[1-9]|refusing|unknown phase' "$d/campaign.log"; then
    echo "$(date) dry pass failed, the real pass is not started"
    exit 1
fi
# without a working detach of the accounting programs the other three phases still run
if grep -qE 'acct (on|off) leaves' "$d/campaign.log" || [ ! -s "$d/res/b1c.jsonl" ]; then
    echo "$(date) the accounting helper failed in the dry pass, the real pass runs without b1c"
    PH="setup b9s b13s ramp"
fi
for f in b9s b13s ramp; do
    [ -s "$d/res/$f.jsonl" ] || { echo "$(date) dry pass left no $f.jsonl, the real pass is not started"; exit 1; }
done
# the dry rows leave the result directory of the dut before the real pass appends to the same files
$DUT 'mkdir -p /root/res-dry && mv /root/res/b1c* /root/res/b9s* /root/res/b13s* /root/res/ramp* /root/res-dry/' < /dev/null
echo "$(date) dry pass clean, starting the real pass"
exec bash "$SRC/workload/campaign.sh" 20530 "$HOME/rfm-ctl" $PH
