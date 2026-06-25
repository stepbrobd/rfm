#!/usr/bin/env nu

# Per-agent kernel BPF-map memory and per-flow-table occupancy, under whatever
# external flood is running (start gen.nu on the peer FIRST with the desired flow
# count -- vary --flows to sweep cardinality). For each in-kernel eBPF agent it
# attributes the agent's own maps (those that appear after the agent starts),
# sums their locked kernel memory, and for each per-flow hash table reports the
# capacity (max_entries) and current occupancy. This shows that rfm holds NO
# per-flow kernel table (constant ring + exact counters), hsflowd holds none, and
# netobserv holds a per-CPU/aggregated flow hash that fills and CAPS as the active
# flow count grows past its max_entries. Run on the DUT; reads /tmp/kmem.json.

const LIB = path self | path dirname | path join "lib.nu"
use $LIB *

def map-ids [] {
    ^bpftool map show -j | from json | get id
}

# sum bytes_memlock over the maps whose id is in $ids
def memlock-of [ids: list<any>] {
    let xs = (
        ^bpftool map show -j
        | from json
        | where {|m| $m.id in $ids}
        | get bytes_memlock?
        | compact
    )
    if ($xs | is-empty) { 0 } else {
        $xs | math sum
    }
}

# per-flow hash tables among the agent's maps (capacity >= 512 excludes tiny
# counter/config maps), with capacity and current entry count
def flow-tables [ids: list<any>] {
    ^bpftool map show -j
    | from json
    | where {|m| ($m.id in $ids) and (($m.type | str contains "hash")) and (($m.max_entries? | default 0) >= 512)}
    | each {|m|
        let dumped = (^bpftool map dump id $m.id -j | complete)
        let entries = if $dumped.exit_code == 0 { ($dumped.stdout | from json | length) } else { -1 }
        {name: $m.name, type: $m.type, max_entries: $m.max_entries, memlock_kb: ($m.bytes_memlock / 1024 | math round), entries: $entries}
    }
}

# kill stray agents so each measurement starts clean
def kill-agents [] {
    ^pkill -KILL -f netobserv-ebpf-agent | complete | ignore
    ^pkill -KILL -x hsflowd | complete | ignore
    ^pkill -KILL -f "rfm agent" | complete | ignore
    null
}

def main [
  --iface: string = "eno1np0"
  --n: int = 100        # sample rate (memory is independent of N, but match the run)
  --warmup: int = 10    # settle so the flow table fills
] {
    kill-agents
    sleep 2sec
    let base_ids = (map-ids)

    # rfm
    let toml = $'[agent]
interfaces=["($iface)"]
[agent.bpf]
sample_rate=($n)
[agent.prometheus]
host="127.0.0.1"
port=9669
'
    let r = (rfm-start $toml)
    sleep ($warmup * 1sec)
    let rfm_ids = map-ids | where {|i| $i not-in $base_ids}
    let rfm_mem = (memlock-of $rfm_ids)
    let rfm_ft = (flow-tables $rfm_ids)
    rfm-stop $r.jid
    sleep 2sec

    # netobserv
    let flp = '{"pipeline":[{"name":"writer","follows":"preset-ingester"}],"parameters":[{"name":"writer","write":{"type":"stdout"}}]}'
    let neto_sh = $"#!/usr/bin/env bash
export INTERFACES=($iface)
export SAMPLING=($n)
export EXPORT=direct-flp
export FLP_CONFIG='($flp)'
exec netobserv-ebpf-agent
"
    $neto_sh | save --force /tmp/kmem-neto.sh
    ^chmod +x /tmp/kmem-neto.sh
    ^bash -c "nohup /tmp/kmem-neto.sh >/dev/null 2>/tmp/kmem-neto.log & echo $! > /tmp/kmem-neto.pid"
    sleep ($warmup * 1sec)
    let neto_ids = map-ids | where {|i| $i not-in $base_ids}
    let neto_mem = (memlock-of $neto_ids)
    let neto_ft = (flow-tables $neto_ids)
    ^pkill -KILL -f netobserv-ebpf-agent | complete | ignore
    sleep 2sec

    # hsflowd EPCAP
    let hsf_mod = (
        which hsflowd
        | get 0.path
        | path dirname
        | path join ".." "lib" "hsflowd" "modules"
        | path expand
    )
    $'sflow {
  agent = ($iface)
  collector { ip = 127.0.0.1  udpport = 6343 }
  epcap { dev = ($iface)  sampling = ($n) }
}
' | save --force /tmp/kmem-hsf.conf
    ^bash -c $"nohup hsflowd -d -f /tmp/kmem-hsf.conf -l ($hsf_mod) > /tmp/kmem-hsf.log 2>&1 &"
    sleep ($warmup * 1sec)
    let hsf_ids = map-ids | where {|i| $i not-in $base_ids}
    let hsf_mem = (memlock-of $hsf_ids)
    let hsf_ft = (flow-tables $hsf_ids)
    ^pkill -KILL -x hsflowd | complete | ignore
    sleep 1sec

    let rows = [
        {
            agent: "rfm"
            map_mem_kb: ($rfm_mem / 1024 | math round)
            flow_tables: $rfm_ft
        }
        {
            agent: "netobserv"
            map_mem_kb: ($neto_mem / 1024 | math round)
            flow_tables: $neto_ft
        }
        {
            agent: "hsflowd"
            map_mem_kb: ($hsf_mem / 1024 | math round)
            flow_tables: $hsf_ft
        }
    ]
    $rows | to json | save --force /tmp/kmem.json
    $rows
}
