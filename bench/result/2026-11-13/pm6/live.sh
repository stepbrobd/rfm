#!/usr/bin/env bash
# copy the dut results to res-live every 5 minutes while job 20529 runs, in case the walltime cuts a phase
O=~/rfm-pm6
mkdir -p $O/res-live
while oarstat -fj 20529 | grep -q "state = Running"; do
    ip=$(grep -m1 -oE "dut ctl 172\.16\.[0-9.]+" $O/campaign.log 2>/dev/null | cut -d" " -f3)
    [ -n "$ip" ] && scp -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 "root@$ip:/root/res/*" $O/res-live/ 2>/dev/null
    sleep 300
done
