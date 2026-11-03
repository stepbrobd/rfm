{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };

  kernels = [
    "linuxPackages_6_12"
    "linuxPackages_6_18"
    "linuxPackages_7_2"
  ];

  pairName = attr: "k" + std.replaceStrings [ "_" ] [ "" ] (std.removePrefix "linuxPackages_" attr);

  hostIP = i: end: "192.168.1.${toString (10 * i + end)}";

  mkNode =
    attr: ip:
    { pkgs, ... }:
    {
      imports = [ (common.mkBase ip) ];

      boot.kernelPackages = std.mkForce pkgs.${attr};

      services.rfm = {
        enable = true;
        settings.agent = {
          interfaces = [
            "eth1"
            "lo"
          ];
          bpf.sample_rate = 1;
          prometheus.port = 9669;
        };
      };
    };
in
{
  name = "rfm-versions";

  inherit (common) interactive;

  nodes = std.listToAttrs (
    std.concatLists (
      std.imap1 (i: attr: [
        {
          name = "${pairName attr}a";
          value = mkNode attr (hostIP i 1);
        }
        {
          name = "${pairName attr}b";
          value = mkNode attr (hostIP i 2);
        }
      ]) kernels
    )
  );

  testScript = common.helpers + ''
    pairs = [ ${
      std.concatStringsSep ", " (
        std.imap1 (
          i: attr: ''(${pairName attr}a, ${pairName attr}b, "${hostIP i 1}", "${hostIP i 2}")''
        ) kernels
      )
    } ]

    for a, b, a_ip, b_ip in pairs:
      with subtest(b.name):
        for m in (a, b):
          m.start()
        for m in (a, b):
          m.wait_for_unit("rfm.service")
          m.wait_for_open_port(9669)
        print(b.succeed("uname -r"))

        b.succeed("bpftool net show | grep rfm_tc_ingress")
        b.succeed("bpftool net show | grep rfm_tc_egress")
        b.succeed("iperf3 -s -D -p 5201")

        assert_rx_matches_nic(a, b, b_ip)

        for m, end in ((a, 1), (b, 2)):
          m.succeed(
            "ip link add link eth1 name eth1.100 type vlan proto 802.1ad id 100",
            "ip link add link eth1.100 name eth1.100.200 mtu 1492 type vlan proto 802.1Q id 200",
            f"ip addr add 10.43.0.{end}/24 dev eth1.100.200",
            "ip link set eth1.100 up",
            "ip link set eth1.100.200 up",
          )
        assert_rx_matches_nic(a, b, "10.43.0.2")

        for m, end, peer in ((a, 1, b_ip), (b, 2, a_ip)):
          m.succeed(
            f"ip link add vxlan42 type vxlan id 42 dev eth1 remote {peer} dstport 4789",
            f"ip addr add 10.42.0.{end}/24 dev vxlan42",
            "ip link set vxlan42 up",
          )
        assert_rx_matches_nic(a, b, "10.42.0.2")

        a.succeed(f"ping -6 -c 5 fd00::{b_ip.split('.')[3]}")
        wait_for_positive_metric(b, "rfm_flow_packets", ifname="eth1", direction="ingress", proto="58")

        for m in (a, b):
          m.shutdown()
  '';
}
