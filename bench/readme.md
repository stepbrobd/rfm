# RFM Single Node Microbenchmark

Datapath overhead and sampling accuracy related statistics are collected on one
node on G5K. We use kernel pktgen on a veth pair and RFM monitors the peer.
"Ground truth" numbers will be from pktgen's exact send counts and RFM's per-CPU
interface counters.

## Kadeploy

Before running the actual benchmark, Kadeploy image (should already be cached)
is required.

Go onto G5K frontend and reserve an interactive job, and install Nix on the
compute node.

Clone the repo:

```sh
git clone https://github.com/stepbrobd/rfm
```

Build the benchmark image:

```sh
nix run nixpkgs#nix-output-monitor -- build .#bench --no-link --json > result.json
```

Copy the closure to the shared NFS between compute node and frontend:

```sh
cp -rL $(jq -r '.[0].outputs.out' result.json) ~/g5k-image
chmod +rw ~/g5k-image
rm result.json
```

Exit out of the current compute node and back to frontend. Then reserve however
many nodes needed for benchmark:

```sh
oarsub -I -t deploy # -l nodes=2,walltime=2
```

Kadeploy (for x86_64-linux jobs):

```sh
kadeploy3 -a ~/g5k-image/nixos-x86_64-linux.yaml # -M
```

## Setup

Deploy G5K Kadeploy image, copy this directory to the node and run as root:

```sh
scp -r bench/workload root@<node>:/root/
```

## Run

```sh
# overhead vs sample rate
nu workload/overhead.nu

# per flow accuracy
nu workload/accuracy.nu --n 100 --m 10000
python3 workload/analyze.py --csv /tmp/rfm-accuracy-N100-M10000.csv --rate 100 --flows 1000

# ring buffer size / wakeup_batch sweep
nu workload/tune.nu

# multi core scaling
# note: one pinned pktgen thread per core and keep cores <= half the node's hw thread
# so the generator does not starve rx-softirq and collector
nu workload/scale.nu --cores "1 2 4 8 16 32" --n 100
```

Each script takes `--flags` (run with `--help` to list them). Also, scripts will
print tables (except for `accuracy.nu` also writes a CSV for `analyze.py`).

## Expected results

- Interface counters are exact (100%) at every sample rate
- Sampled flow estimates track 1/N
- Ring buffer drops should appear only at low N like N = 1
- Higher N > 1 (or a larger `ring_buf_size`) should remove the drops
- With sampling, the datapath should scale linearly across cores
- Without samlpling, ring buffer and single consumer should plateau
- Per-flow relative error follows sqrt(N/P)
  (<https://dl.acm.org/doi/10.1145/637201.637225>)
- Flow coverage should drop as P / N go below 1

## On 2 or more nodes with KaVLAN

The veth bench cannot exercise the real NIC driver path (hardware IRQ, NAPI,
RSS). For that use two nodes with their data NIC in an isolated KaVLAN, so the
traffic neither touches nor is disturbed by the production network.

Reserve two nodes (or more) in the same cluster with routed VLAN and deploy:

```sh
# say we are on grenoble
oarsub -t deploy \
  -l "{type='kavlan'}/vlan=1+{cluster='dahu'}/host=2,walltime=6:0:0" \
  ~/kavlan-deploy.sh
```

`~/kavlan-deploy.sh`:

```sh
#!/usr/bin/env bash
VLAN=$(kavlan -V -j "$OAR_JOB_ID")
kavlan -e -i "$VLAN" -j "$OAR_JOB_ID"
kadeploy3 -a ~/g5k-image/nixos-x86_64-linux.yaml -f "$OAR_NODE_FILE" --vlan "$VLAN"
sleep 21000
```

Use a routed `kavlan` (not `kavlan-local`) because dahu only have a single
usable NIC, unrouted vlan would leave the nodes unreachable. After deploy the
nodes get isolated IPs and answer at `<node>-kavlan-<vlanid>` (e.g.
`dahu-7-kavlan-4.grenoble.g5k`).

Copy `workload/` to both nodes. Start the generator first (its flood must be
flowing before the device under test measures), then run the DUT sweeps. The DUT
NIC MAC is the generator's `--dstmac`.

```sh
# generator node: sustained flood, many flows for RSS spread (detached)
nu workload/gen.nu --dst <dut-ip> --dstmac <dut-mac> --threads 1 --count 1200000000

# DUT: overhead vs sample rate on the real NIC (descending, N=1 last)
nu workload/realnic.nu --ns "1024 100 10 1" --secs 15

# DUT: hardware RSS multi-queue sweep (resets the NIC via ethtool -L, detached)
nu workload/rss.nu --queues "1 2 4 8 16 32 64" --ns "100 1"

# DUT: head-to-head vs libpcap baselines (system-wide busy cores per agent)
# need softflowd and pmacct
nu workload/headtohead.nu --n 100
```

Run the DUT scripts detached (a line-rate flood stalls the management SSH on the
single NIC). Read results from `/tmp/{realnic,rss}.json`.
