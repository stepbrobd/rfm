#!/usr/bin/env bash
# accuracy cells on dahu (Intel X710 10 GbE, i40e), job 3169855: the four offload cases and the merge sweep.
# one port, so control rides the kavlan names, and the channels and rings stay at the NIC default
export SRC=$HOME/rfm-bench-x SITE=grenoble IF=ens3f0np0 CTL_IF= CH= RING= IMG=$HOME/rfm-image
exec bash $SRC/workload/campaign.sh 3169855 $HOME/rfm-acc setup b1 b2
