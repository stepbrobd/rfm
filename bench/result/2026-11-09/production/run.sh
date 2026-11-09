#!/usr/bin/env bash
# production window extraction, read-only: the VictoriaMetrics window first so the extra scrapes
# below do not enter the footprint, then two hours of chained /metrics deltas and flow table
# snapshots, then the increase() check over the same two hours and the tables
set -u
cd "$(dirname "$0")"
OUT=${1:-prod}
N="kongo roraima isere timah morasko lagern highline rysy lantau odake baldy butte cradle toompea walberla"
mkdir -p "$OUT"
date -u +%FT%TZ > "$OUT/start"
python3 -I vm.py --out "$OUT" $N 2> "$OUT/vm.log"
python3 -I scrape.py --out "$OUT" --secs 7800 --every 60 $N 2> "$OUT/scrape.log" &
python3 -I flowsize.py --out "$OUT" --secs 7200 --every 20 $N 2> "$OUT/flowsize.log" &
wait
python3 -I vm.py --out "$OUT" --bias $N 2>> "$OUT/vm.log"
python3 -I analyze.py "$OUT" > "$OUT/tables.md"
date -u +%FT%TZ > "$OUT/end"
