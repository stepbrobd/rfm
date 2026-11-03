#!/usr/bin/env nu

# Build the BPF objects progbench times: the agent's own bpf/rfm_tc.c at three
# ISA levels, and the ablation variants of rfm_variants.c. Runs on the dev box
# from the repository root inside the dev shell, writes <out>/<label>.o and
# <out>/variants.json, which progbench.nu reads on the node.

def main [--out: string = "result-progbench"] {
    mkdir $out
    let inc = (^pkg-config --cflags-only-I libbpf | str trim | split row " ")
    let base = [
        "--target=bpfel"
        "-O2"
        "-g"
        "-Wall"
        "-Wno-missing-declarations"
        "-Wno-unused-function"
        "-Ibpf"
        "-Ibpf/include"
        "-Ibpf/include/vmlinux/x86_64"
        "-D__TARGET_ARCH_x86"
    ]
    let agent = [
        [label, mcpu];
        [agent_v1, v1]
        [agent_v3, v3]
        [agent_v4, v4]
    ]
    for a in $agent {
        ^clang ...$base ...$inc $"-mcpu=($a.mcpu)" -c bpf/rfm_tc.c -o $"($out)/($a.label).o"
    }
    # label, ISA level and the macros of rfm_variants.c
    let variants = [
        [label, mcpu, defs];
        [empty, v3, [RFM_EMPTY=1]]
        [var_mod_hash_v1, v1, []]
        [var_mod_hash, v3, []]
        [thresh_hash, v3, [RFM_DRAW=1]]
        [mod_array, v3, [RFM_CTR=1]]
        [thresh_array, v3, [RFM_DRAW=1 RFM_CTR=1]]
        [skip_array, v3, [RFM_DRAW=2 RFM_CTR=1]]
        [thresh_array_lazy_nowake, v3, [RFM_DRAW=1 RFM_CTR=1 RFM_LAZY=1 RFM_WAKE=1]]
        [skip_array_lazy_nowake, v3, [RFM_DRAW=2 RFM_CTR=1 RFM_LAZY=1 RFM_WAKE=1]]
        [nocounter_thresh, v3, [RFM_CTR=2 RFM_DRAW=1]]
        [sampled_mod, v3, [RFM_SAMPLED=1]]
        [sampled_thresh, v3, [RFM_SAMPLED=1 RFM_DRAW=1]]
        [sampled_skip, v3, [RFM_SAMPLED=1 RFM_DRAW=2]]
        [sampled_thresh_lazy_nowake, v3, [RFM_SAMPLED=1 RFM_DRAW=1 RFM_LAZY=1 RFM_WAKE=1]]
        [xdp_empty, v3, [RFM_XDP=1 RFM_EMPTY=1 RFM_CTR=1]]
        [xdp_skip_array, v3, [RFM_XDP=1 RFM_CTR=1 RFM_DRAW=2 RFM_LAZY=1 RFM_WAKE=1]]
    ]
    for v in $variants {
        let defs = $v.defs | each {|d| $"-D($d)" }
        ^clang ...$base ...$inc $"-mcpu=($v.mcpu)" ...$defs -c bench/progbench/bpf/rfm_variants.c -o $"($out)/($v.label).o"
    }
    let labels = $agent | get label | append ($variants | get label)
    $labels | to json | save -f $"($out)/variants.json"
    print $"built ($labels | length) objects in ($out)"
}
