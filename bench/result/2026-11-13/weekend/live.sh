#!/usr/bin/env bash
# copy the dut results to res-live every 10 minutes while job 20530 waits or runs
O=~/rfm-weekend
mkdir -p $O/res-live
while oarstat -fj 20530 | grep -qE "state = (Running|Waiting|Launching|toLaunch)"; do
    ip=$(grep -m1 -oE "dut ctl 172\.16\.[0-9.]+" $O/campaign.log 2>/dev/null | cut -d" " -f3)
    [ -n "$ip" ] && scp -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=20 "root@$ip:/root/res/*" $O/res-live/ 2>/dev/null
    sleep 600
done
