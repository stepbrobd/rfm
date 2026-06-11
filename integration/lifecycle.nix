{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-lifecycle";

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  nodes = {
    inherit (common)
      machine1
      machine2
      machine3
      machine4
      ;
  };

  testScript = common.helpers + ''
    start_all()
    machines = [machine1, machine2, machine3, machine4]

    # service lifecycle and basic checks
    for m in machines:
      m.wait_for_unit("multi-user.target")
      m.succeed("which rfm")
      m.succeed("ip -4 -br addr show dev eth1")

      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)
      m.succeed("curl -sf http://localhost:9669/metrics | grep rfm_")

    # health and error metrics
    for m in machines:
      metrics = m.succeed("curl -sf http://localhost:9669/metrics")
      require_metric(metrics, "rfm_collector_active_flows")
      require_metric(metrics, "rfm_collector_dropped_events_total")
      require_metric(metrics, "rfm_collector_forced_evictions_total")
      require_metric(metrics, "rfm_errors_total", subsystem="bpf_map")
      require_metric(metrics, "rfm_errors_total", subsystem="ipfix")
      require_metric(metrics, "rfm_errors_total", subsystem="ring_buffer")
  '';
}
