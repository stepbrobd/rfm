#!/usr/bin/env bash
# seventh run of job 20530, behind the sixth: the bulk TCP windows of the XDP comparison at two MTUs
# of the dut with nothing and with an empty XDP program attached (b9m), with the power settings of
# the dut fixed, from the harness in rfm-bench-m (the weekend's objects)
# It waits while the sixth run (pid 1866112) or any campaign.sh of the job is alive, makes a dry
# pass and starts the real pass only when the dry pass is clean, left a row for every cell and
# left the dut at its MTU of 1500
DUT="ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 root@172.16.208.15"
sleep 120
while kill -0 1866112 2> /dev/null || pgrep -f 'workload/campaign.sh 20530' > /dev/null; do
    sleep 60
done
grep -q 'campaign done' "$HOME/rfm-z/campaign.log" 2> /dev/null || echo "$(date) the sixth run left no campaign done"
echo "$(date) starting the dry pass"
export SRC=$HOME/rfm-bench-m
export ROUNDS=5 PWR=fixed
d=$HOME/rfm-m-dry
DRY=1 bash "$SRC/workload/campaign.sh" 20530 "$d" setup b9m
if ! grep -q 'campaign done' "$d/campaign.log" || grep -qE '^exit=[1-9]|refusing|unknown phase|power [a-z0-9]+ reads back' "$d/campaign.log"; then
    echo "$(date) dry pass failed, the real pass is not started"
    exit 1
fi
for m in 1500 1700; do
    for l in none xdp_empty; do
        grep -q "\"$l gro=on\"" "$d/res/b9m-fixed-mtu$m.jsonl" 2> /dev/null || {
            echo "$(date) dry pass left no row for $l at an MTU of $m, the real pass is not started"
            exit 1
        }
    done
done
mtu=$($DUT 'cat /sys/class/net/ens1f0np0/mtu' < /dev/null)
if [ "$mtu" != 1500 ]; then
    echo "$(date) the dut's MTU reads '$mtu' after the dry pass, the real pass is not started"
    exit 1
fi
$DUT 'mkdir -p /root/res-dry5 && mv /root/res/b9m* /root/res-dry5/' < /dev/null
echo "$(date) dry pass clean, starting the real pass: b9m"
exec bash "$SRC/workload/campaign.sh" 20530 "$HOME/rfm-m" setup b9m
