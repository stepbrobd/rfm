#!/usr/bin/env bash
# the night job 20519 ended its phases at 03:05 with walltime to 08:30. Once its nodes are redeployed on
# the v2026.1109.0 image, run setup and pm (and b4 and b1 if they fit) there, ahead of job 20520
set -u
cd ~ || exit 1
while kill -0 "$1" 2> /dev/null; do sleep 15; done
log=~/rfm-n2/kadeploy.log
if ! grep -q 'The deployment is successful on nodes' "$log" || [ "$(grep -c '^spirou-[78]\.louvain' "$log")" != 2 ]; then
    echo "$(date '+%F %T') redeploy failed, nothing started" >> ~/rfm-n2/launch.log
    exit 1
fi
# pm takes about 2 h 5 min, b4 35 min and b1 47 min, the job ends at 08:30
now=$(date +%H%M)
if [ "$now" -lt 0500 ]; then
    phases="setup pm b4 b1"
elif [ "$now" -lt 0615 ]; then
    phases="setup pm"
else
    echo "$(date '+%F %T') too late for pm, nothing started" >> ~/rfm-n2/launch.log
    exit 0
fi
echo "$(date '+%F %T') starting $phases" >> ~/rfm-n2/launch.log
SRC=~/rfm-d2-src exec bash ~/rfm-d2-src/workload/campaign.sh 20519 ~/rfm-n2 $phases > ~/rfm-n2/driver.out 2>&1 < /dev/null
