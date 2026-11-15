#!/usr/bin/env bash
# one round of the flow coverage phase on what is left of job 20529, to check it before the weekend
export SRC=$HOME/rfm-bench-w R3="1"
exec bash $SRC/workload/campaign.sh 20529 $HOME/rfm-cov setup b4cov
