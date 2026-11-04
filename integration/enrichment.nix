{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-enrichment";

  inherit (common) interactive;

  nodes.machine1 =
    { pkgs, ... }:
    {
      imports = [ common.machine1 ];

      services.bird = {
        enable = true;
        package = pkgs.bird3;
        config = ''
          router id 192.168.1.1;

          protocol device {
          }

          protocol kernel kernel4 {
            ipv4 {
              import none;
              export all;
            };
          }

          protocol bgp from_machine2 {
            local 192.168.1.1 as 65001;
            neighbor 192.168.1.2 as 65002;
            ipv4 {
              import all;
              import table on;
              export none;
            };
          }

          protocol bgp from_machine3 {
            local 192.168.1.1 as 65001;
            neighbor 192.168.1.3 as 65003;
            ipv4 {
              import all;
              import table on;
              export none;
            };
          }

          protocol bmp rfm {
            station address ip 127.0.0.1 port 11019;
            monitoring rib in pre_policy;
            tx buffer limit 64;
          }
        '';
      };

      systemd.services.bird.after = [ "rfm.service" ];
      systemd.services.bird.requires = [ "rfm.service" ];
    };

  nodes.machine2 =
    { pkgs, ... }:
    {
      imports = [ common.machine2 ];

      services.bird = {
        enable = true;
        package = pkgs.bird3;
        config = ''
          router id 192.168.1.2;

          protocol device {
          }

          filter export_machine1 {
            if source = RTS_STATIC then {
              bgp_community.add((65002, 100));
              bgp_large_community.add((65002, 1, 100));
              bgp_path.prepend(65002);
              accept;
            }
            reject;
          }

          protocol static static4 {
            ipv4;
            route 203.0.113.0/24 blackhole;
          }

          protocol bgp to_machine1 {
            local 192.168.1.2 as 65002;
            neighbor 192.168.1.1 as 65001;
            ipv4 {
              import none;
              export filter export_machine1;
            };
          }
        '';
      };
    };

  nodes.machine3 =
    { pkgs, ... }:
    {
      imports = [ common.machine3 ];

      services.bird = {
        enable = true;
        package = pkgs.bird3;
        config = ''
          router id 192.168.1.3;

          protocol device {
          }

          filter export_machine1 {
            if source = RTS_STATIC then {
              bgp_community.add((65003, 200));
              bgp_large_community.add((65003, 2, 200));
              bgp_path.prepend(65003);
              accept;
            }
            reject;
          }

          protocol static static4 {
            ipv4;
            route 198.51.100.0/24 blackhole;
          }

          protocol bgp to_machine1 {
            local 192.168.1.3 as 65003;
            neighbor 192.168.1.1 as 65001;
            ipv4 {
              import none;
              export filter export_machine1;
            };
          }
        '';
      };
    };

  testScript = common.helpers + ''
    def lookup_mmdb_asn(machine, ip: str) -> str:
      return machine.succeed(
        "mmdblookup --file \"$(cat /etc/rfm-test-asn-db)\" "
        f"--ip {ip} autonomous_system_number "
        "| grep -Eo '[0-9]+ <uint32>' | cut -d' ' -f1"
      ).strip()

    start_all()
    for m in [machine1, machine2, machine3]:
      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)

    # machine1 exposes the local BMP listener for Bird
    machine1.wait_until_succeeds("ss -ltn | grep LISTEN | grep ':11019'")
    machine1.wait_until_succeeds("ss -tn | grep ESTAB | grep ':11019'")

    # Bird runs on machine1-3 to feed controlled routes into BMP/RIB
    for m in [machine1, machine2, machine3]:
      m.wait_for_unit("bird.service")

    machine1.wait_until_succeeds("birdc show protocols all from_machine2 | grep Established")
    machine1.wait_until_succeeds("birdc show protocols all from_machine3 | grep Established")
    machine2.wait_until_succeeds("birdc show protocols all to_machine1 | grep Established")
    machine3.wait_until_succeeds("birdc show protocols all to_machine1 | grep Established")
    machine1.wait_until_succeeds("birdc show route 203.0.113.0/24 all | grep 203.0.113.0/24")
    machine1.wait_until_succeeds("birdc show route 198.51.100.0/24 all | grep 198.51.100.0/24")
    machine1.wait_until_succeeds("ip route show 203.0.113.0/24 | grep 192.168.1.2")
    machine1.wait_until_succeeds("ip route show 198.51.100.0/24 | grep 192.168.1.3")

    # optional enrichment backends
    machine1.wait_until_succeeds("rfm rib lookup --json 203.0.113.7 | grep -q '\"origin_asn\": 65002'")
    machine1.wait_until_succeeds("rfm rib lookup --json 198.51.100.7 | grep -q '\"origin_asn\": 65003'")

    machine1.succeed("ping -c 2 -W 1 203.0.113.7 || true")
    machine1.succeed("ping -c 2 -W 1 198.51.100.7 || true")
    machine1.succeed("ip route add 8.8.8.0/24 via 192.168.1.2")
    machine1.succeed(
      "python3 -c 'import socket; sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
      "[sock.sendto(b\"rfm-mmdb-test\", (\"8.8.8.8\", 33434)) for _ in range(5)]; sock.close()'"
    )

    google_asn = lookup_mmdb_asn(machine1, "8.8.8.8")
    wait_for_positive_metric(machine1, "rfm_flow_packets_total", ifname="eth1", direction="egress", dst_asn="65002")
    wait_for_positive_metric(machine1, "rfm_flow_packets_total", ifname="eth1", direction="egress", dst_asn="65003")
    wait_for_positive_metric(machine1, "rfm_flow_packets_total", ifname="eth1", direction="egress", dst_asn=google_asn)
  '';
}
