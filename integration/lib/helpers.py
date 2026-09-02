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
  return vals

def require_positive(metrics: str, name: str, **labels: str) -> list[float]:
  vals = require_metric(metrics, name, **labels)
  assert any(val > 0 for val in vals), f"{name} {labels} has no positive samples: {vals}"
  return vals

def iface_counters(machine, ifname: str) -> tuple[int, int, int, int]:
  """rfm and kernel rx counters of ifname read back to back.

  Returns (rfm packets, rfm bytes, kernel packets, kernel bytes) so a test can
  compare deltas of the exact per-CPU counters against the NIC statistics.
  """
  out = machine.succeed(
    "curl -sf http://localhost:9669/metrics; echo ---; "
    f"cat /sys/class/net/{ifname}/statistics/rx_packets "
    f"/sys/class/net/{ifname}/statistics/rx_bytes"
  )
  metrics, kernel = out.split("---\n")
  rx_packets, rx_bytes = (int(x) for x in kernel.split())
  return (
    int(sum(metric_values(metrics, "rfm_interface_rx_packets_total", ifname=ifname))),
    int(sum(metric_values(metrics, "rfm_interface_rx_bytes_total", ifname=ifname))),
    rx_packets,
    rx_bytes,
  )

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
