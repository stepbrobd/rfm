{ inputs, std }:

let
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
        bpftools
        iperf3
        iproute2
        netcat-openbsd
      ];
    };
in
{
  inherit mkBase;

  interactive = {
    sshBackdoor.enable = true;
    defaults =
      { pkgs, ... }:
      {
        environment.systemPackages = with pkgs; [
          alacritty.terminfo
          bpftrace
          ethtool
          tcpdump
          xdp-tools
        ];
      };
  };

  helpers = std.readFile ./helpers.py;

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
