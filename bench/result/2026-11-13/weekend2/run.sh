#!/usr/bin/env bash
# follow-on to the weekend campaign of job 20530: waits for its `campaign done`, then runs the
# cohort sweep (b13) and the power settings switched one at a time (pm3) from the harness in
# rfm-bench-w2. The eBPF monitors only, the libpcap ones stall the bulk TCP of the mixed load
while ! grep -q 'campaign done' "$HOME/rfm-weekend/campaign.log" 2> /dev/null; do
    pgrep -f 'campaign.sh 20530 .*/rfm-weekend ' > /dev/null || { echo "$(date) first driver gone without campaign done, starting anyway"; break; }
    sleep 60
done
echo "$(date) starting follow-on"
export SRC=$HOME/rfm-bench-w2
export R3="1 2 3 4 5" R2="1 2 3 4 5" RB4="1 2 3 4 5"
export ACC="rfm_acc netobserv hsflowd"
exec bash $SRC/workload/campaign.sh 20530 $HOME/rfm-weekend2 setup b13 pm3
