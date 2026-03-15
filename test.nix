{ inputs, std, ... }:

let
  mkMachine =
    ip:
    { pkgs, ... }:
    {
      imports = [ inputs.self.nixosModules.default ];

      services.rfm = {
        enable = true;
        interface = "eth1";
        settings = { };
      };

      boot.kernelPackages = pkgs.linuxPackages_latest;
      boot.supportedFilesystems.zfs = std.mkForce false;
      boot.initrd.supportedFilesystems.zfs = std.mkForce false;
      boot.kernel.sysctl = {
        "net.ipv4.conf.all.rp_filter" = 0;
        "net.ipv4.conf.default.rp_filter" = 0;
        "net.ipv4.conf.eth1.rp_filter" = 0;
      };

      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [
        {
          address = ip;
          prefixLength = 24;
        }
      ];

      environment.systemPackages = with pkgs; [
        alacritty.terminfo
        bpftools
        bpftrace
        ethtool
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

  nodes.machine1 = mkMachine "192.168.1.1";
  nodes.machine2 = mkMachine "192.168.1.2";
  nodes.machine3 = mkMachine "192.168.1.3";
  nodes.machine4 = mkMachine "192.168.1.4";

  testScript = ''
    start_all()

    for m in machines:
      m.wait_for_unit("multi-user.target")
      m.succeed("which rfm")
      m.succeed("ip -4 -br addr show dev eth1")

      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)
      m.succeed("curl -sf http://localhost:9669/metrics | grep rfm_")
  '';
}
