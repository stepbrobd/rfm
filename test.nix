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
            eviction_timeout = "30s";
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
    import time

    def metric_lines(metrics, name):
      prefix = name + "{"
      bare = name + " "
      return [
        line for line in metrics.splitlines()
        if line.startswith(prefix) or line.startswith(bare)
      ]

    def metric_values(metrics, name, **labels):
      vals = []
      for line in metric_lines(metrics, name):
        if all(f'{key}="{value}"' in line for key, value in labels.items()):
          vals.append(float(line.split()[-1]))
      return vals

    def require_metric(metrics, name, **labels):
      vals = metric_values(metrics, name, **labels)
      if vals:
        return vals

      lines = metric_lines(metrics, name)
      raise AssertionError(
        f"missing {name} with labels {labels}, candidates: {lines}"
      )
      return vals

    def require_positive(metrics, name, **labels):
      vals = require_metric(metrics, name, **labels)
      assert any(val > 0 for val in vals), f"{name} {labels} has no positive samples: {vals}"
      return vals

    def send_bmp(machine):
      machine.succeed(r"""
        wire1='\x03\x00\x00\x00\x5d\x00\x03\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x02\x02\x00\x00\xfd\xea\xc0\x00\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x2d\x02\x00\x00\x00\x12\x40\x01\x01\x00\x40\x02\x04\x02\x01\xfd\xea\x40\x03\x04\xc0\x00\x02\x01\x18\xcb\x00\x71'
        wire2='\x03\x00\x00\x00\x5d\x00\x03\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x02\x03\x00\x00\xfd\xeb\xc0\x00\x02\x03\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x2d\x02\x00\x00\x00\x12\x40\x01\x01\x00\x40\x02\x04\x02\x01\xfd\xeb\x40\x03\x04\xc0\x00\x02\x01\x18\xc6\x33\x64'
        printf '%b%b' "$wire1" "$wire2" | nc -N 127.0.0.1 11019
      """)

    start_all()

    # --- phase 1: service lifecycle and basic checks ---
    for m in machines:
      m.wait_for_unit("multi-user.target")
      m.succeed("which rfm")
      m.succeed("ip -4 -br addr show dev eth1")

      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)
      m.succeed("curl -sf http://localhost:9669/metrics | grep rfm_")

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
    machine1.succeed("ping -c 2 -W 1 8.8.8.8 || true")
    time.sleep(2)

    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    require_positive(metrics1, "rfm_flow_packets", ifname="eth1", direction="egress", dst_asn="65002")
    require_positive(metrics1, "rfm_flow_packets", ifname="eth1", direction="egress", dst_asn="65003")
    require_positive(metrics1, "rfm_flow_packets", ifname="eth1", direction="egress", dst_asn="15169")

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
      require_metric(metrics, "rfm_errors_total", subsystem="ring_buffer")
  '';
}
