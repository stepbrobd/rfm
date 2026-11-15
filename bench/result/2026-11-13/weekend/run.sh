#!/usr/bin/env bash
# weekend of job 20530 on the release image: five rounds everywhere, pmacctd and softflowd in the
# accuracy phases, the paper gaps first and the rest of the campaign after them
export SRC=$HOME/rfm-bench-w
export R3="1 2 3 4 5" R2="1 2 3 4 5" RB4="1 2 3 4 5"
export ACC="rfm_acc netobserv hsflowd pmacctd softflowd"
exec bash $SRC/workload/campaign.sh 20530 $HOME/rfm-weekend setup b1 b12 b2 b4 b11 b3 b7 b5 b8 b9 pm sparse pm6 b4cov
