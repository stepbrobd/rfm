#!/usr/bin/env bash
# the wait condition of the sixth wrapper alone, term by term and whole, then with a pid and a job
# that do not exist, where it has to read free
kill -0 1836045 2> /dev/null && echo "term 1 (pid 1836045 alive): true" || echo "term 1 (pid 1836045 alive): false"
pgrep -f 'workload/campaign.sh 20530' > /dev/null && echo "term 2 (a campaign.sh of the job): true" || echo "term 2 (a campaign.sh of the job): false"
pgrep -af 'workload/campaign.sh 20530' | cut -c1-120
if kill -0 1836045 2> /dev/null || pgrep -f 'workload/campaign.sh 20530' > /dev/null; then echo "whole: busy"; else echo "whole: free"; fi
if kill -0 4194000 2> /dev/null || pgrep -f 'workload/campaign.sh 99999' > /dev/null; then echo "control: busy"; else echo "control: free"; fi
if kill -0 4194000 2> /dev/null || pgrep -f 'workload/campaign.sh 20530' > /dev/null; then echo "second term alone: busy"; else echo "second term alone: free"; fi
if kill -0 1836045 2> /dev/null || pgrep -f 'workload/campaign.sh 99999' > /dev/null; then echo "first term alone: busy"; else echo "first term alone: free"; fi
