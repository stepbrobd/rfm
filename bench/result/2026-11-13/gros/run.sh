#!/usr/bin/env bash
# accuracy cells on gros (ConnectX-4 Lx 25 GbE, mlx5), job 7023876: the four offload cases and the merge sweep
export SRC=$HOME/rfm-bench-x SITE=nancy IF=eno1np0 CTL_IF=eno2np1 CH= RING= IMG=$HOME/rfm-image
exec bash $SRC/workload/campaign.sh 7023876 $HOME/rfm-acc setup b1 b2
