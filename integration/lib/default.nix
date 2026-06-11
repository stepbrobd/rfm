{ inputs, std }:

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
            address = "fd00::${std.elemAt (std.splitString "." ip) 3}";
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

          substituters = std.mkForce [
            "https://cache.ysun.co?priority=10"
            "https://cache.nixos.org?priority=15"
          ];

          trusted-public-keys = std.mkForce [
            "cache.ysun.co-1:WxPYwT5g3kt9XhUhHPpNLZKI9HIOsVVAuqSHpok8Qt4="
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
          ];
        };
      };
    };
in
{
  inherit mkBase;

  # shared python helpers prepended to test scripts
  helpers = std.readFile ./helpers.py;

  # https://github.com/stepbrobd/rfm/actions/runs/27352866052/job/80819677363#step:5:5108
  # https://github.com/stepbrobd/rfm/actions/runs/27347885470/job/80814124422#step:5:4534
  overlay = _: prev: {
    bird3 = prev.bird3.overrideAttrs (prev: {
      patches = (prev.patches or [ ]) ++ [ ./bmp.patch ];
    });
  };

  # each machine have different config to cover more code paths
  machine1 =
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
            template_refresh = "1s";
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
    };

  machine2 = {
    imports = [ (mkBase "192.168.1.2") ];

    services.rfm = {
      enable = true;
      settings.agent = {
        interfaces = [ "eth1" ];
        bpf.sample_rate = 10;
        prometheus.port = 9669;
      };
    };
  };

  machine3 = {
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
  };

  machine4 = {
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
}
