{ inputs, std, ... }:

let
  # shared base config for all machines
  mkBase =
    ip:
    { pkgs, ... }:
    {
      imports = [ inputs.self.nixosModules.default ];

      boot.kernelPackages = pkgs.linuxPackages_latest;
      boot.supportedFilesystems.zfs = std.mkForce false;
      boot.initrd.supportedFilesystems.zfs = std.mkForce false;
      boot.kernel.sysctl = {
        "net.ipv4.conf.all.rp_filter" = 0;
        "net.ipv4.conf.default.rp_filter" = 0;
        "net.ipv4.conf.eth1.rp_filter" = 0;
      };

      networking.firewall.enable = false;
      networking.interfaces.eth1 = {
        ipv4.addresses = [
          {
            address = ip;
            prefixLength = 24;
          }
        ];
        ipv6.addresses = [
          {
            address = "fd00::${builtins.elemAt (std.splitString "." ip) 3}";
            prefixLength = 64;
          }
        ];
      };

      environment.systemPackages = with pkgs; [
        alacritty.terminfo
        bpftools
        bpftrace
        ethtool
        iperf3
        iproute2
        netcat-openbsd
        tcpdump
        xdp-tools
      ];

      nix = {
        channel.enable = false;
        nixPath = [ "nixpkgs=${pkgs.path}" ];

        settings = {
          accept-flake-config = true;
          allow-import-from-derivation = true;
          builders-use-substitutes = true;
          fallback = true;
          keep-build-log = true;
          keep-derivations = true;
          keep-env-derivations = true;
          keep-failed = true;
          keep-going = true;
          keep-outputs = true;
          sandbox = true;
          use-xdg-base-directories = true;
          warn-dirty = false;

          trusted-users = [
            "root"
            "@wheel"
          ];

          experimental-features = [
            "auto-allocate-uids"
            "ca-derivations"
            "cgroups"
            "flakes"
            "impure-derivations"
            "nix-command"
            "pipe-operators"
          ];

          extra-substituters = [
            "https://cache.nixos.org?priority=10"
            "https://cache.garnix.io?priority=20"
            "https://nixos-raspberrypi.cachix.org?priority=20"
            "https://nix-community.cachix.org?priority=20"
            "https://nixpkgs-update.cachix.org?priority=20"
            "https://colmena.cachix.org?priority=20"
            "https://stepbrobd.cachix.org?priority=20"
            "https://cache.ysun.co/public?priority=30"
          ];

          trusted-public-keys = [
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
            "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
            "nixos-raspberrypi.cachix.org-1:4iMO9LXa8BqhU+Rpg6LQKiGa2lsNh/j2oiYLNOQ5sPI="
            "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
            "nixpkgs-update.cachix.org-1:6y6Z2JdoL3APdu6/+Iy8eZX2ajf09e4EE9SnxSML1W8="
            "colmena.cachix.org-1:7BzpDnjjH8ki2CT3f6GdOk7QAzPOl+1t3LvTLXqYcSg="
            "stepbrobd.cachix.org-1:Aa5jdkPVrCOvzaLTC0kVP5PYQ5BtNnLg1tG1Qa/QuE4="
            "public:Y9EARSt+KLUY1JrY4X8XWmzs6uD+Zh2hRqN9eCUg55U="
          ];
        };
      };
    };
in
{
  name = "rfm";

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  # each machine gets different config to exercise more code paths
  nodes.machine1 =
    { pkgs, ... }:
    {
      imports = [ (mkBase "192.168.1.1") ];

      environment.systemPackages = with pkgs; [
        libmaxminddb
        python3
      ];
      environment.etc."rfm-test-asn-db".text = "${pkgs.dbip-asn-lite}/share/dbip/dbip-asn-lite.mmdb";

      services.rfm = {
        enable = true;
        settings.agent = {
          interfaces = [
            "eth1"
            "lo"
          ];
          bpf.sample_rate = 1;
          collector = {
            max_flows = 1024;
            eviction_timeout = "5s";
          };
          ipfix = {
            host = "127.0.0.1";
            port = 4739;
            bind.host = "127.0.0.1";
          };
          prometheus = {
            host = "::1";
            port = 9669;
          };
          enrich = {
            mmdb = {
              asn_db = "${pkgs.dbip-asn-lite}/share/dbip/dbip-asn-lite.mmdb";
              city_db = "${pkgs.dbip-city-lite}/share/dbip/dbip-city-lite.mmdb";
            };
            rib.bmp = {
              host = "127.0.0.1";
              port = 11019;
            };
          };
        };
      };

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
      imports = [ (mkBase "192.168.1.2") ];

      services.rfm = {
        enable = true;
        settings.agent = {
          interfaces = [ "eth1" ];
          bpf.sample_rate = 10;
          prometheus.port = 9669;
        };
      };

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
      imports = [ (mkBase "192.168.1.3") ];

      services.rfm = {
        enable = true;
        settings.agent = {
          interfaces = [
            "eth1"
            "lo"
          ];
          bpf.sample_rate = 1;
          collector.max_flows = 4096;
          prometheus.port = 9669;
        };
      };

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

  nodes.machine4 =
    { pkgs, ... }:
    {
      imports = [ (mkBase "192.168.1.4") ];
      # single interface, sample every packet, bind to specific address
      services.rfm = {
        enable = true;
        settings.agent = {
          interfaces = [ "eth1" ];
          bpf.sample_rate = 1;
          prometheus = {
            host = "0.0.0.0";
            port = 9669;
          };
        };
      };
    };

  testScript = ''
    import base64
    import ipaddress
    import json
    import struct
    import time

    def metric_lines(metrics: str, name: str) -> list[str]:
      prefix = name + "{"
      bare = name + " "
      return [
        line for line in metrics.splitlines()
        if line.startswith(prefix) or line.startswith(bare)
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

    def wait_for_positive_metric(machine: Machine, name: str, timeout_s: float = 10, **labels: str) -> list[float]:
      deadline = time.time() + timeout_s
      last_metrics = ""
      while time.time() < deadline:
        last_metrics = machine.succeed("curl -sf http://localhost:9669/metrics")
        vals = metric_values(last_metrics, name, **labels)
        if any(val > 0 for val in vals):
          return vals
        time.sleep(1)
      return require_positive(last_metrics, name, **labels)

    def lookup_mmdb_asn(machine: Machine, ip: str) -> str:
      return machine.succeed(
        "mmdblookup --file \"$(cat /etc/rfm-test-asn-db)\" "
        f"--ip {ip} autonomous_system_number "
        "| grep -Eo '[0-9]+ <uint32>' | cut -d' ' -f1"
      ).strip()

    def json_lines(machine: Machine, path: str) -> list[dict]:
      raw = machine.succeed(f"test -s {path} && cat {path}")
      return [json.loads(line) for line in raw.splitlines() if line.strip()]

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

    def send_bmp(machine: Machine) -> None:
      wire = b"".join(
        [
          bmp_route("203.0.113.0/24", 65002, "192.0.2.2"),
          bmp_route("198.51.100.0/24", 65003, "192.0.2.3"),
        ]
      )
      payload = base64.b64encode(wire).decode()
      machine.succeed(f"printf '%s' '{payload}' | base64 -d | nc -N 127.0.0.1 11019")

    def start_ipfix_listener(machine: Machine) -> None:
      script = base64.b64encode(
        b"import json\n"
        b"import socket\n"
        b"import struct\n"
        b"\n"
        b"sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        b"sock.bind((\"127.0.0.1\", 4739))\n"
        b"with open(\"/tmp/ipfix.ready\", \"w\", encoding=\"utf-8\") as ready:\n"
        b"  ready.write(\"ready\\n\")\n"
        b"\n"
        b"with open(\"/tmp/ipfix.jsonl\", \"a\", encoding=\"utf-8\") as out:\n"
        b"  while True:\n"
        b"    data, _ = sock.recvfrom(65535)\n"
        b"    if len(data) < 16:\n"
        b"      continue\n"
        b"\n"
        b"    version, length, export_time, sequence_num, observation_domain_id = struct.unpack(\"!HHIII\", data[:16])\n"
        b"    set_ids = []\n"
        b"    offset = 16\n"
        b"    limit = min(length, len(data))\n"
        b"\n"
        b"    while offset + 4 <= limit:\n"
        b"      set_id, set_len = struct.unpack(\"!HH\", data[offset:offset + 4])\n"
        b"      if set_len < 4 or offset + set_len > limit:\n"
        b"        break\n"
        b"      set_ids.append(set_id)\n"
        b"      offset += set_len\n"
        b"\n"
        b"    out.write(\n"
        b"      json.dumps(\n"
        b"        {\n"
        b"          \"version\": version,\n"
        b"          \"length\": length,\n"
        b"          \"export_time\": export_time,\n"
        b"          \"sequence_num\": sequence_num,\n"
        b"          \"observation_domain_id\": observation_domain_id,\n"
        b"          \"set_ids\": set_ids,\n"
        b"        }\n"
        b"      )\n"
        b"      + \"\\n\"\n"
        b"    )\n"
        b"    out.flush()\n"
      ).decode()
      machine.succeed("rm -f /tmp/ipfix.ready /tmp/ipfix.jsonl /tmp/ipfix.out /tmp/ipfix.err /tmp/ipfix-listener.py")
      machine.succeed(
        f"printf '%s' '{script}' | base64 -d > /tmp/ipfix-listener.py"
      )
      machine.succeed("python3 -m py_compile /tmp/ipfix-listener.py")
      machine.succeed("nohup python3 /tmp/ipfix-listener.py </dev/null >/tmp/ipfix.out 2>/tmp/ipfix.err &")
      machine.wait_until_succeeds("test -s /tmp/ipfix.ready")

    start_all()

    # --- phase 1: service lifecycle and basic checks ---
    for m in machines:
      m.wait_for_unit("multi-user.target")
      m.succeed("which rfm")
      m.succeed("ip -4 -br addr show dev eth1")

      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)
      m.succeed("curl -sf http://localhost:9669/metrics | grep rfm_")

    start_ipfix_listener(machine1)

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

    # --- phase 2: TCX program verification (bpftool, not tc filter) ---
    machine1.succeed("bpftool net show | grep rfm_tc_ingress")
    machine1.succeed("bpftool net show | grep rfm_tc_egress")

    machine2.succeed("bpftool net show | grep rfm_tc_ingress")
    machine2.succeed("bpftool net show | grep rfm_tc_egress")

    # --- phase 2b: multi-interface verification ---
    machine1.succeed("ping -c 5 127.0.0.1")
    time.sleep(1)
    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics1, "rfm_interface_rx_packets_total", ifname="lo", family="ipv4")
    require_positive(metrics1, "rfm_interface_tx_packets_total", ifname="lo", family="ipv4")
    assert 'ifname="eth1"' in metrics1, "missing eth1 interface in metrics"

    # --- phase 3: TCP traffic with iperf3 ---
    machine2.succeed("iperf3 -s -D -p 5201")
    time.sleep(1)

    machine1.succeed("iperf3 -c 192.168.1.2 -p 5201 -t 2 -P 1")
    time.sleep(2)

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

    # --- phase 4: UDP traffic with iperf3 ---
    machine1.succeed("iperf3 -c 192.168.1.2 -p 5201 -u -t 2 -b 10M")
    time.sleep(2)

    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics1, "rfm_flow_packets", ifname="eth1", direction="egress", proto="17")

    # --- phase 4b: ipfix export ---
    machine1.wait_until_succeeds("test -s /tmp/ipfix.jsonl")
    time.sleep(5)
    packets = json_lines(machine1, "/tmp/ipfix.jsonl")
    assert any(
      packet.get("version") == 10
      and packet.get("observation_domain_id") == 1
      and 2 in packet.get("set_ids", [])
      for packet in packets
    ), f"missing ipfix template packet in {packets}"
    assert any(
      packet.get("version") == 10
      and 256 in packet.get("set_ids", [])
      for packet in packets
    ), f"missing ipv4 ipfix data packet in {packets}"
    assert max((packet.get("sequence_num", -1) for packet in packets), default = -1) >= 1, (
      f"expected multiple ipfix data records in {packets}"
    )

    # --- phase 5: controlled ping with known packet size ---
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

    # --- phase 6: IPv6 traffic ---
    machine1.succeed("ping -6 -c 5 -s 100 fd00::2")
    time.sleep(2)

    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics1, "rfm_interface_tx_packets_total", ifname="eth1", family="ipv6")

    # --- phase 7: optional enrichment backends ---
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

    # --- phase 8: bidirectional verification ---
    metrics2 = machine2.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics2, "rfm_flow_packets", ifname="eth1", direction="ingress")

    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics1, "rfm_flow_packets", ifname="eth1", direction="egress")

    # --- phase 9: health and error metrics ---
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
