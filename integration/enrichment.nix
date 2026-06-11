{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-enrichment";

  # allow nodes overlay
  node.pkgsReadOnly = false;

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  nodes.machine1 =
    { pkgs, ... }:
    {
      imports = [ common.machine1 ];

      # TODO: remove after upstream merge the fix
      nixpkgs.overlays = [ common.overlay ];

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

      # TODO: remove after upstream merge the fix
      nixpkgs.overlays = [ common.overlay ];

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

      # TODO: remove after upstream merge the fix
      nixpkgs.overlays = [ common.overlay ];

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
    import base64
    import ipaddress
    import struct

    def lookup_mmdb_asn(machine, ip: str) -> str:
      return machine.succeed(
        "mmdblookup --file \"$(cat /etc/rfm-test-asn-db)\" "
        f"--ip {ip} autonomous_system_number "
        "| grep -Eo '[0-9]+ <uint32>' | cut -d' ' -f1"
      ).strip()

    def prefix_nlri(prefix: str) -> bytes:
      net = ipaddress.ip_network(prefix, strict=True)
      octets = (net.prefixlen + 7) // 8
      return bytes([net.prefixlen]) + net.network_address.packed[:octets]

    def bmp_route(prefix: str, origin: int, peer_addr: str, next_hop: str = "192.0.2.1") -> bytes:
      peer = ipaddress.ip_address(peer_addr)
      hop = ipaddress.ip_address(next_hop)
      assert peer.version == 4
      assert hop.version == 4
      assert 0 <= origin <= 0xFFFF

      as_path = bytes([2, 1]) + struct.pack(">H", origin)
      path_attrs = b"".join(
        [
          bytes([0x40, 1, 1, 0]),
          bytes([0x40, 2, len(as_path)]) + as_path,
          bytes([0x40, 3, 4]) + hop.packed,
        ]
      )

      bgp_payload = (
        struct.pack(">H", 0)
        + struct.pack(">H", len(path_attrs))
        + path_attrs
        + prefix_nlri(prefix)
      )
      bgp_update = b"\xff" * 16 + struct.pack(">HB", 19 + len(bgp_payload), 2) + bgp_payload
      peer_header = b"".join(
        [
          bytes([0, 0x40]),
          b"\x00" * 8,
          b"\x00" * 12 + peer.packed,
          struct.pack(">I", origin),
          peer.packed,
          b"\x00" * 8,
        ]
      )

      return b"\x03" + struct.pack(">IB", 6 + len(peer_header) + len(bgp_update), 0) + peer_header + bgp_update

    def send_bmp(machine) -> None:
      wire = b"".join(
        [
          bmp_route("203.0.113.0/24", 65002, "192.0.2.2"),
          bmp_route("198.51.100.0/24", 65003, "192.0.2.3"),
        ]
      )
      payload = base64.b64encode(wire).decode()
      machine.succeed(f"printf '%s' '{payload}' | base64 -d | nc -N 127.0.0.1 11019")

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
    # Keep the Bird topology for real routes. Feed deterministic BMP updates
    # into rfm because Bird 3 BMP in this topology only emits EOR.
    send_bmp(machine1)
    machine1.wait_until_succeeds(
      "journalctl -u rfm --no-pager | grep 'bmp route monitoring applied' | grep 'reach=1'"
    )

    machine1.succeed("ping -c 2 -W 1 203.0.113.7 || true")
    machine1.succeed("ping -c 2 -W 1 198.51.100.7 || true")
    machine1.succeed("ip route add 8.8.8.0/24 via 192.168.1.2")
    machine1.succeed(
      "python3 -c 'import socket; sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
      "[sock.sendto(b\"rfm-mmdb-test\", (\"8.8.8.8\", 33434)) for _ in range(5)]; sock.close()'"
    )

    google_asn = lookup_mmdb_asn(machine1, "8.8.8.8")
    wait_for_positive_metric(machine1, "rfm_flow_packets", ifname="eth1", direction="egress", dst_asn="65002")
    wait_for_positive_metric(machine1, "rfm_flow_packets", ifname="eth1", direction="egress", dst_asn="65003")
    wait_for_positive_metric(machine1, "rfm_flow_packets", ifname="eth1", direction="egress", dst_asn=google_asn)
  '';
}
