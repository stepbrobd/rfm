import time


def metric_lines(metrics: str, name: str) -> list[str]:
  prefix = name + "{"
  bare = name + " "
  return [
    line for line in metrics.splitlines()
    if line.startswith((prefix, bare))
  ]

def metric_values(metrics: str, name: str, **labels: str) -> list[float]:
  vals = []
  for line in metric_lines(metrics, name):
    if all(f'{key}="{value}"' in line for key, value in labels.items()):
      vals.append(float(line.split()[-1]))
  return vals

def require_metric(metrics: str, name: str, **labels: str) -> list[float]:
  vals = metric_values(metrics, name, **labels)
  if vals:
    return vals

  lines = metric_lines(metrics, name)
  raise AssertionError(
    f"missing {name} with labels {labels}, candidates: {lines}"
  )

def require_positive(metrics: str, name: str, **labels: str) -> list[float]:
  vals = require_metric(metrics, name, **labels)
  assert any(val > 0 for val in vals), f"{name} {labels} has no positive samples: {vals}"
  return vals

def iface_counters(machine, ifname: str, direction: str = "rx") -> tuple[int, int, int, int]:
  """rfm and kernel packets and bytes of ifname in direction rx or tx, read back to back."""
  out = machine.succeed(
    "curl -sf http://localhost:9669/metrics; echo ---; "
    f"cat /sys/class/net/{ifname}/statistics/{direction}_packets "
    f"/sys/class/net/{ifname}/statistics/{direction}_bytes"
  )
  metrics, kernel = out.split("---\n")
  packets, octets = (int(x) for x in kernel.split())
  return (
    int(sum(metric_values(metrics, f"rfm_interface_{direction}_packets_total", ifname=ifname))),
    int(sum(metric_values(metrics, f"rfm_interface_{direction}_bytes_total", ifname=ifname))),
    packets,
    octets,
  )

def assert_rx_matches_nic(sender, receiver, dst: str, ifname: str = "eth1") -> None:
  """rfm's rx counters of ifname on receiver match the kernel's over an iperf3 tcp run from sender to dst, whose segments gro merges before the tc hook."""
  before = iface_counters(receiver, ifname)
  sender.succeed(f"iperf3 -c {dst} -p 5201 -t 2 -P 1")
  time.sleep(2)
  after = iface_counters(receiver, ifname)
  rfm_pkts, rfm_bytes, nic_pkts, nic_bytes = (a - b for a, b in zip(after, before))
  print(f"{receiver.name} rx to {dst}: rfm {rfm_pkts} pkts {rfm_bytes} bytes, nic {nic_pkts} pkts {nic_bytes} bytes")
  assert nic_pkts > 100, f"iperf3 produced too few packets: {nic_pkts}"
  assert abs(rfm_pkts - nic_pkts) <= 4, f"rx packets: rfm {rfm_pkts} vs nic {nic_pkts}"
  assert abs(rfm_bytes - nic_bytes) <= 4 * 1514, f"rx bytes: rfm {rfm_bytes} vs nic {nic_bytes}"

def wait_for_positive_metric(machine, name: str, timeout_s: float = 10, **labels: str) -> list[float]:
  deadline = time.time() + timeout_s
  last_metrics = ""
  while time.time() < deadline:
    last_metrics = machine.succeed("curl -sf http://localhost:9669/metrics")
    vals = metric_values(last_metrics, name, **labels)
    if any(val > 0 for val in vals):
      return vals
    time.sleep(1)
  return require_positive(last_metrics, name, **labels)
