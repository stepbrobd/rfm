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
      # multi-interface: eth1 + lo, sample every packet, custom port
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
            host = "::";
            port = 9669;
          };
        };
      };
    };

  nodes.machine2 =
    { pkgs, ... }:
    {
      imports = [ (mkBase "192.168.1.2") ];
      # single interface, different sample rate, default port
      services.rfm = {
        enable = true;
        settings.agent = {
          interfaces = [ "eth1" ];
          bpf.sample_rate = 10;
          prometheus.port = 9669;
        };
      };
    };

  nodes.machine3 =
    { pkgs, ... }:
    {
      imports = [ (mkBase "192.168.1.3") ];
      # multi-interface, sample every packet, larger flow table
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

    start_all()

    # --- phase 1: service lifecycle and basic checks ---
    for m in machines:
      m.wait_for_unit("multi-user.target")
      m.succeed("which rfm")
      m.succeed("ip -4 -br addr show dev eth1")

      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)
      m.succeed("curl -sf http://localhost:9669/metrics | grep rfm_")

    # --- phase 2: TC program verification ---
    # machine1 has multi-interface (eth1 + lo)
    machine1.succeed("tc filter show dev eth1 ingress | grep rfm")
    machine1.succeed("tc filter show dev eth1 egress | grep rfm")
    machine1.succeed("tc filter show dev lo ingress | grep rfm")
    machine1.succeed("tc filter show dev lo egress | grep rfm")

    # machine2 has single interface (eth1 only)
    machine2.succeed("tc filter show dev eth1 ingress | grep rfm")
    machine2.succeed("tc filter show dev eth1 egress | grep rfm")

    # --- phase 3: TCP traffic with iperf3 ---
    machine2.succeed("iperf3 -s -D -p 5201")
    time.sleep(1)

    machine1.succeed("iperf3 -c 192.168.1.2 -p 5201 -t 2 -P 1")
    time.sleep(2)

    # sender should see tx bytes
    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    assert "rfm_interface_tx_bytes_total" in metrics1, "missing tx bytes on sender"

    # receiver should see rx bytes
    metrics2 = machine2.succeed("curl -sf http://localhost:9669/metrics")
    assert "rfm_interface_rx_bytes_total" in metrics2, "missing rx bytes on receiver"

    # TCP flow metrics with proto=6
    assert 'proto="6"' in metrics1 or 'proto="6"' in metrics2, \
      "missing TCP flow metric"

    # --- phase 4: UDP traffic with iperf3 ---
    machine1.succeed("iperf3 -c 192.168.1.2 -p 5201 -u -t 2 -b 10M")
    time.sleep(2)

    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    assert 'proto="17"' in metrics1, "missing UDP flow metric (proto=17)"

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
    assert 'family="ipv6"' in metrics1, "missing ipv6 family label"

    # --- phase 7: bidirectional verification ---
    metrics2 = machine2.succeed("curl -sf http://localhost:9669/metrics")
    assert 'direction="ingress"' in metrics2, "missing ingress direction on receiver"

    metrics1 = machine1.succeed("curl -sf http://localhost:9669/metrics")
    assert 'direction="egress"' in metrics1, "missing egress direction on sender"

    # --- phase 8: health and error metrics ---
    for m in machines:
      metrics = m.succeed("curl -sf http://localhost:9669/metrics")
      assert "rfm_collector_active_flows" in metrics, "missing active_flows"
      assert "rfm_collector_dropped_events_total" in metrics, "missing dropped_events"
      assert "rfm_collector_forced_evictions_total" in metrics, "missing forced_evictions"
      assert "rfm_errors_total" in metrics, "missing errors_total"
  '';
}
