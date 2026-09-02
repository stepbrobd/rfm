{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-traffic";

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  nodes = { inherit (common) machine1 machine2; };

  testScript = common.helpers + ''
    start_all()
    for m in [machine1, machine2]:
      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)

    # TCP traffic with iperf3
    machine2.succeed("iperf3 -s -D -p 5201")
    time.sleep(1)

    before = iface_counters(machine2, "eth1")
    machine1.succeed("iperf3 -c 192.168.1.2 -p 5201 -t 2 -P 1")
    time.sleep(2)

    # gro merges the received tcp segments into large skbs before the tc
    # hook runs, the exact counters must still report wire packets and wire
    # bytes, which is what the nic statistics count
    after = iface_counters(machine2, "eth1")
    rfm_pkts, rfm_bytes, nic_pkts, nic_bytes = (a - b for a, b in zip(after, before))
    print(f"rx over iperf3: rfm {rfm_pkts} pkts {rfm_bytes} bytes, nic {nic_pkts} pkts {nic_bytes} bytes")
    assert nic_pkts > 100, f"iperf3 produced too few packets: {nic_pkts}"
    assert abs(rfm_pkts - nic_pkts) <= 4, f"rx packets: rfm {rfm_pkts} vs nic {nic_pkts}"
    assert abs(rfm_bytes - nic_bytes) <= 4 * 1514, f"rx bytes: rfm {rfm_bytes} vs nic {nic_bytes}"

    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics1, "rfm_interface_tx_bytes_total", ifname="eth1", family="ipv4")
    require_positive(metrics1, "rfm_flow_packets", ifname="eth1", direction="egress", proto="6")

    metrics2 = machine2.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics2, "rfm_interface_rx_bytes_total", ifname="eth1", family="ipv4")
    sampled = require_positive(metrics2, "rfm_flow_sampled_packets", ifname="eth1", direction="ingress", proto="6")
    scaled = require_positive(metrics2, "rfm_flow_packets", ifname="eth1", direction="ingress", proto="6")
    assert any(val == samp * 10 for val in scaled for samp in sampled), (
      f"expected scaled flow packets to be sample_rate x sampled packets, got sampled={sampled} scaled={scaled}"
    )

    # UDP traffic with iperf3
    machine1.succeed("iperf3 -c 192.168.1.2 -p 5201 -u -t 2 -b 10M")
    time.sleep(2)

    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics1, "rfm_flow_packets", ifname="eth1", direction="egress", proto="17")

    # IPv6 traffic
    machine1.succeed("ping -6 -c 5 -s 100 fd00::2")
    time.sleep(2)

    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics1, "rfm_interface_tx_packets_total", ifname="eth1", family="ipv6")

    # bidirectional verification
    metrics2 = machine2.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics2, "rfm_flow_packets", ifname="eth1", direction="ingress")

    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics1, "rfm_flow_packets", ifname="eth1", direction="egress")
  '';
}
