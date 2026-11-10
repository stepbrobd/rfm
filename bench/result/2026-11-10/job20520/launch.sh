#!/usr/bin/env bash
# job 20520 on the v2026.1109.0 image: setup, sparse (the b3 cells at N of 10000 and 100000, the b1 cells
# at 10000), then pm (the b3 cells at the default power settings and with turbo and C6 off). The driver
# waits for the job to run and deploy, and a loop copies the dut's results every 5 minutes, since the
# driver copies them only at the end of each phase and pm may run into the walltime.
set -eu
mkdir -p ~/rfm-d2/res-live
cd ~
SRC=~/rfm-d2-src setsid nohup bash ~/rfm-d2-src/workload/campaign.sh 20520 ~/rfm-d2 setup sparse pm > ~/rfm-d2/driver.out 2>&1 < /dev/null &
drv=$!
echo "driver pid $drv"
setsid nohup bash -c '
    while kill -0 '"$drv"' 2> /dev/null; do
        sleep 300
        ip=$(grep -oE "dut ctl 172\.16\.[0-9.]+" ~/rfm-d2/campaign.log 2> /dev/null | tail -1 | cut -d" " -f3)
        [ -n "$ip" ] && scp -q -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "root@$ip:/root/res/*" ~/rfm-d2/res-live/ 2> /dev/null
    done' > /dev/null 2>&1 < /dev/null &
echo "copy loop pid $!"
