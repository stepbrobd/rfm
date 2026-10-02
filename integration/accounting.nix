{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-accounting";

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  nodes = { inherit (common) machine3 machine4; };

  testScript = common.helpers + ''
    start_all()
    for m in [machine3, machine4]:
      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)

    def ipv4_counters(machine, direction: str) -> tuple[int, int]:
      metrics = machine.succeed("curl -sf http://localhost:9669/metrics")
      return (
        int(sum(require_metric(metrics, f"rfm_interface_{direction}_packets_total", ifname="eth1", family="ipv4"))),
        int(sum(require_metric(metrics, f"rfm_interface_{direction}_bytes_total", ifname="eth1", family="ipv4"))),
      )

    # one exchange resolves the neighbor and creates every series read
    # below, so the window holds the measured echo traffic alone
    machine3.succeed("ping -c 1 192.168.1.4")
    time.sleep(1)

    paths = [(machine3, "tx"), (machine4, "rx"), (machine4, "tx"), (machine3, "rx")]
    before = [(iface_counters(m, "eth1", d), ipv4_counters(m, d)) for m, d in paths]

    # 10 echo requests and 10 replies of 542 bytes on the wire, a 500 byte
    # payload behind 8 bytes of icmp, 20 of ipv4 and 14 of ethernet
    machine3.succeed("ping -c 10 -i 0.2 -s 500 192.168.1.4")
    time.sleep(2)

    after = [(iface_counters(m, "eth1", d), ipv4_counters(m, d)) for m, d in paths]

    for (m, d), (iface_before, ipv4_before), (iface_after, ipv4_after) in zip(paths, before, after):
      # the exact counters follow the nic statistics, as traffic checks for rx
      rfm_pkts, rfm_bytes, nic_pkts, nic_bytes = (a - b for a, b in zip(iface_after, iface_before))
      print(f"{m.name} eth1 {d}: rfm {rfm_pkts} pkts {rfm_bytes} bytes, nic {nic_pkts} pkts {nic_bytes} bytes")
      assert abs(rfm_pkts - nic_pkts) <= 4, f"{m.name} {d} packets: rfm {rfm_pkts} vs nic {nic_pkts}"
      assert abs(rfm_bytes - nic_bytes) <= 4 * 1514, f"{m.name} {d} bytes: rfm {rfm_bytes} vs nic {nic_bytes}"

      # and the ipv4 series holds the echo traffic, no more and no less
      pkts, octets = (a - b for a, b in zip(ipv4_after, ipv4_before))
      assert (pkts, octets) == (10, 10 * 542), (
        f"{m.name} {d} ipv4: {pkts} pkts {octets} bytes, expected 10 pkts {10 * 542} bytes"
      )
  '';
}
