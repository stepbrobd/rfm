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

    # the control socket answers the birdc style commands
    for m in machines:
      status = m.succeed("rfm status")
      assert "interfaces" in status and "eth1" in status, f"unexpected status output: {status}"
      assert "sampling" in status, f"unexpected status output: {status}"
      m.succeed("rfm flows count")
      m.succeed("rfm config show | grep -q interfaces")
      m.succeed("rfm set sample-rate 7")
      assert "1 in 7" in m.succeed("rfm status"), "sample rate change not visible in status"
      m.succeed("rfm status --json | grep -q '\"rate\": 7'")
      m.succeed("rfm set sample-rate 1")
  '';
}
