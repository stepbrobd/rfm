{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-accounting";

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  nodes = { inherit (common) machine3 machine4; };

  testScript = ''
    import time

    start_all()
    for m in [machine3, machine4]:
      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)

    # controlled ping with known packet size
    # 10 pings, 500 byte payload = 528 bytes/pkt (500 + 20 IP + 8 ICMP)
    machine3.succeed("ping -c 10 -s 500 192.168.1.4")
    time.sleep(2)

    metrics3 = machine3.succeed("curl -sf http://localhost:9669/metrics")
    # tx bytes for eth1/ipv4 should reflect the ping traffic
    for line in metrics3.splitlines():
      if "rfm_interface_tx_bytes_total" in line and 'family="ipv4"' in line and 'ifname="eth1"' in line:
        val = float(line.split()[-1])
        assert val >= 5000, f"tx bytes too low: {val}, expected >= 5000"
        break
  '';
}
