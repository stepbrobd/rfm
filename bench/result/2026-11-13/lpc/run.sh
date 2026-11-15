#!/usr/bin/env bash
# first real cells of the libpcap accuracy counts, on what is left of job 20529 after pm6
export SRC=$HOME/rfm-bench-w R3="1 2" ACC="pmacctd softflowd"
exec bash $SRC/workload/campaign.sh 20529 $HOME/rfm-lpc setup b1
