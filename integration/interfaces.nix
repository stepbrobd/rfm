{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-interfaces";

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  nodes = { inherit (common) machine1 machine2; };

  testScript = common.helpers + ''
    start_all()
    for m in [machine1, machine2]:
      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)

    # TCX program verification (bpftool, not tc filter)
    machine1.succeed("bpftool net show | grep rfm_tc_ingress")
    machine1.succeed("bpftool net show | grep rfm_tc_egress")

    machine2.succeed("bpftool net show | grep rfm_tc_ingress")
    machine2.succeed("bpftool net show | grep rfm_tc_egress")

    # multi-interface verification
    machine1.succeed("ping -c 5 127.0.0.1")
    time.sleep(1)
    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics1, "rfm_interface_rx_packets_total", ifname="lo", family="ipv4")
    require_positive(metrics1, "rfm_interface_tx_packets_total", ifname="lo", family="ipv4")
    assert 'ifname="eth1"' in metrics1, "missing eth1 interface in metrics"
  '';
}
