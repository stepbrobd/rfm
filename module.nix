{ std, inputs, ... }:

{ config, pkgs, ... }:

let
  cfg = config.services.rfm;

  toml = pkgs.formats.toml { };

  configFile = toml.generate "rfm.toml" cfg.settings;

  boundPort = std.types.ints.between 1024 65535;
in
{
  options.services.rfm = {
    enable = std.mkEnableOption "RFM (Router Flow Monitor)";

    package = std.mkPackageOption inputs.self.packages.${pkgs.stdenv.hostPlatform.system} "default" { };

    settings = std.mkOption {
      type = std.types.submodule {
        options.agent = std.mkOption {
          type = std.types.submodule {
            options = {
              interfaces = std.mkOption {
                type = std.types.listOf std.types.str;
                description = ''
                  Network interfaces to monitor. Each entry is a Go regular
                  expression matched against system interface names with
                  implicit full-string anchoring. Use `[".*"]` for all
                  interfaces, `["enp.*"]` for the enp prefix, or list
                  exact names like `["eth0"]`. Overlapping patterns are
                  deduplicated by interface index, so `["eth0", "eth.*"]`
                  attaches each interface at most once. Links without an
                  Ethernet header, such as WireGuard, tun or xfrm
                  interfaces, are skipped with a warning.
                '';
                example = [
                  "eth0"
                  "enp.*"
                ];
              };

              bpf = std.mkOption {
                default = { };
                type = std.types.submodule {
                  options = {
                    sample_rate = std.mkOption {
                      type = std.types.ints.positive;
                      default = 100;
                      description = "Sample 1 in N skbs for flow events, an event carries every wire packet of its skb.";
                    };

                    ring_buf_size = std.mkOption {
                      type = std.types.ints.unsigned;
                      default = 0;
                      description = "Size in bytes of the ring buffer of each CPU, 0 derives it from sample_rate: 256 KiB at 1 in 1, half as much for each doubling of the rate, down to 64 KiB from 1 in 4 on.";
                    };

                    wakeup_batch = std.mkOption {
                      type = std.types.ints.unsigned;
                      default = 0;
                      description = "Force a ring buffer wakeup every N flow events a CPU submits over all its interfaces, 0 derives a quarter of the events the ring holds. At most half of them, and a ring_buf_size of 0 grows to hold twice a set batch.";
                    };

                    iface_stats_size = std.mkOption {
                      type = std.types.ints.unsigned;
                      default = 0;
                      description = "Override the BPF iface stats map capacity, 0 keeps the default of 4096 counter keys or the capacity of a pinned map. A set capacity that differs from the pinned one fails the start until the pin is removed or the host reboots.";
                    };

                    iface_slots = std.mkOption {
                      type = std.types.ints.between 0 256;
                      default = 0;
                      description = "Counter slots of the per CPU array, 0 keeps the default of 16 or the slots of a pinned array. An interface past the slots counts in the iface stats map. A set count that differs from the pinned one fails the start until the pin is removed or the host reboots.";
                    };

                    adaptive_sampling = std.mkOption {
                      type = std.types.bool;
                      default = false;
                      description = "Raise the sample rate while the ring buffer drops events and relax it afterwards.";
                    };

                    max_sample_rate = std.mkOption {
                      type = std.types.ints.positive;
                      default = 1000;
                      description = "Upper bound for the adaptive sample rate and for any rate set with `rfm set sample-rate`.";
                    };

                    sampled_only = std.mkOption {
                      type = std.types.bool;
                      default = false;
                      description = "Keep no exact interface counters, a packet the sampling draw passes over then costs only the draw. The interface metrics go away, the flow metrics stay.";
                    };

                    stage_events = std.mkOption {
                      type = std.types.ints.between 1 32;
                      default = 1;
                      description = "Sampled events each CPU stages before it writes them to its ring buffer as one record, 1 writes every event at once. Above 1 needs Linux 6.7 or later without PREEMPT_RT, a timer writes a partial stage within 10 milliseconds, and the wakeup batch counts the events each CPU writes.";
                    };

                    pin_path = std.mkOption {
                      type = std.types.strMatching "(/sys/fs/bpf/[^/]+)?";
                      default = "/sys/fs/bpf/rfm";
                      description = "bpffs directory directly under /sys/fs/bpf that keeps the interface counters across restarts, empty keeps them private to the process.";
                    };
                  };
                };
              };

              collector = std.mkOption {
                default = { };
                type = std.types.submodule {
                  options = {
                    max_flows = std.mkOption {
                      type = std.types.ints.positive;
                      default = 65536;
                      description = "Maximum number of active flows. It also limits the label tuples of the flow metrics, a new tuple with enrichment labels finds room while fewer than max_flows tuples exist or takes the place of the longest idle one a scrape has shown, and otherwise its flow counts under empty labels.";
                    };

                    eviction_timeout = std.mkOption {
                      type = std.types.str;
                      default = "30s";
                      description = "Flow eviction timeout (Go duration).";
                    };

                    active_timeout = std.mkOption {
                      type = std.types.str;
                      default = "60s";
                      description = "Interval after which a live flow is exported as a delta record over IPFIX (Go duration), \"0s\" disables it.";
                    };
                  };
                };
              };

              ipfix = std.mkOption {
                default = { };
                type = std.types.submodule {
                  options = {
                    host = std.mkOption {
                      type = std.types.str;
                      default = "";
                      description = "IPFIX collector host.";
                    };

                    port = std.mkOption {
                      type = std.types.ints.between 0 65535;
                      default = 0;
                      description = "IPFIX collector UDP port, 0 means 4739 when a host is set and no export otherwise.";
                    };

                    bind = std.mkOption {
                      default = { };
                      type = std.types.submodule {
                        options = {
                          host = std.mkOption {
                            type = std.types.str;
                            default = "";
                            description = "IPFIX exporter local source address.";
                          };

                          port = std.mkOption {
                            type = std.types.either (std.types.enum [ 0 ]) boundPort;
                            default = 0;
                            description = "IPFIX exporter local source port (0 = ephemeral).";
                          };
                        };
                      };
                    };

                    template_refresh = std.mkOption {
                      type = std.types.str;
                      default = "60s";
                      description = "How often UDP IPFIX templates are re-sent (Go duration).";
                    };

                    observation_domain_id = std.mkOption {
                      type = std.types.ints.positive;
                      default = 1;
                      description = "IPFIX observation domain id used in exported messages.";
                    };

                    max_message_size = std.mkOption {
                      type = std.types.ints.between 171 65535;
                      default = 1200;
                      description = "Largest IPFIX message in bytes, the UDP payload, keep it at most the path MTU minus 28 bytes for IPv4 or 48 bytes for IPv6.";
                    };
                  };
                };
              };

              prometheus = std.mkOption {
                default = { };
                type = std.types.submodule {
                  options = {
                    host = std.mkOption {
                      type = std.types.str;
                      default = "::1";
                      description = "Prometheus metrics listen address.";
                    };

                    port = std.mkOption {
                      type = boundPort;
                      default = 9669;
                      description = "Prometheus metrics listen port.";
                    };
                  };
                };
              };

              control = std.mkOption {
                default = { };
                type = std.types.submodule {
                  options = {
                    socket = std.mkOption {
                      type = std.types.strMatching "(/run/rfm/[^/]+)?";
                      default = "/run/rfm/rfm.sock";
                      description = "Unix socket the rfm command line talks to, a file directly in /run/rfm, empty disables it.";
                    };
                  };
                };
              };

              enrich = std.mkOption {
                default = { };
                type = std.types.submodule {
                  options = {
                    mmdb = std.mkOption {
                      default = { };
                      type = std.types.submodule {
                        options = {
                          asn_db = std.mkOption {
                            type = std.types.str;
                            default = "";
                            description = "Path to the ASN MMDB database.";
                          };

                          city_db = std.mkOption {
                            type = std.types.str;
                            default = "";
                            description = "Path to the city MMDB database.";
                          };
                        };
                      };
                    };

                    rib = std.mkOption {
                      default = { };
                      type = std.types.submodule {
                        options = {
                          bmp = std.mkOption {
                            default = { };
                            type = std.types.submodule {
                              options = {
                                host = std.mkOption {
                                  type = std.types.str;
                                  default = "";
                                  description = "BMP listen host for live RIB updates.";
                                };

                                port = std.mkOption {
                                  type = std.types.either (std.types.enum [ 0 ]) boundPort;
                                  default = 0;
                                  description = "BMP listen port for live RIB updates, 0 means 11019 when a host is set and no listener otherwise.";
                                };
                              };
                            };
                          };
                        };
                      };
                    };
                  };
                };
              };
            };
          };
        };
      };

      default = { };
      description = "Settings for RFM, serialized to TOML.";
    };
  };

  config = std.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    users.users.rfm = {
      isSystemUser = true;
      group = "rfm";
      description = "Router Flow Monitor agent";
    };
    users.groups.rfm = { };

    systemd.services.rfm = {
      description = "Router Flow Monitor agent";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      startLimitIntervalSec = 0;
      serviceConfig = {
        ExecStartPre = std.optionals (cfg.settings.agent.bpf.pin_path != "") [
          "+${pkgs.coreutils}/bin/chmod 0711 ${std.dirOf cfg.settings.agent.bpf.pin_path}"
          "+${pkgs.coreutils}/bin/install -d -m 0750 -o rfm -g rfm ${cfg.settings.agent.bpf.pin_path}"
        ];
        ExecStart = "${cfg.package}/bin/rfm agent -c ${configFile}";
        Restart = "on-failure";
        RestartSec = "5s";
        User = "rfm";
        Group = "rfm";
        RuntimeDirectory = "rfm";
        RuntimeDirectoryMode = "0750";

        AmbientCapabilities = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_PERFMON"
        ];
        CapabilityBoundingSet = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_PERFMON"
        ];
        NoNewPrivileges = true;

        ProtectSystem = "strict";
        ProtectKernelTunables = true;
        ReadWritePaths = std.optionals (cfg.settings.agent.bpf.pin_path != "") [
          "-${cfg.settings.agent.bpf.pin_path}"
        ];
        ProtectHome = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        ProtectKernelModules = true;
        ProtectClock = true;
        ProtectHostname = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RestrictNamespaces = true;
        SystemCallArchitectures = "native";
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
        ];
      };
    };
  };
}
