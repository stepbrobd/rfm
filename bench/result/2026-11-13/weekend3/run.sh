#!/usr/bin/env bash
# third driver of job 20530: after the first campaign and the follow-on (rfm-weekend2) are both
# done, the replay benchmark (b5) with the objects built from rfm 89cdc2d and a441abf: the agent
# with the stationary first gap, and the skb unit variants skb_unit_array and sampled_skip_skb.
# It waits while the follow-on's wrapper (pid 1174942) or any campaign.sh of the job is alive
sleep 120
while kill -0 1174942 2> /dev/null || pgrep -f 'workload/campaign.sh 20530' > /dev/null; do
    sleep 60
done
grep -q 'campaign done' "$HOME/rfm-weekend2/campaign.log" 2> /dev/null || echo "$(date) follow-on left no campaign done"
echo "$(date) starting third driver"
export SRC=$HOME/rfm-bench-w3
exec bash $SRC/workload/campaign.sh 20530 $HOME/rfm-weekend3 setup b5
