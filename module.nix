{ std, inputs, ... }:

{ config, pkgs, ... }:

let
  cfg = config.services.rfm;

  toml = pkgs.formats.toml { };

  configFile = toml.generate "rfm.toml" cfg.settings;
in
{
  options.services.rfm = {
    enable = std.mkEnableOption "RFM (Router Flow Monitor)";

    package = std.mkPackageOption inputs.self.packages.${pkgs.stdenv.hostPlatform.system} "default" { };

    settings = std.mkOption {
      type = std.types.submodule {
        freeformType = toml.type;

        options.agent = std.mkOption {
          type = std.types.submodule {
            freeformType = toml.type;

            options = {
              interfaces = std.mkOption {
                type = std.types.listOf std.types.str;
                description = ''
                  Network interfaces to monitor. Each entry is a Go regular
                  expression matched against system interface names with
                  implicit full-string anchoring. Use `[".*"]` for all
                  interfaces, `["ranet.*"]` for the ranet prefix, or list
                  exact names like `["eth0"]`. Overlapping patterns are
                  deduplicated by interface index, so `["eth0", "eth.*"]`
                  attaches each interface at most once.
                '';
                example = [
                  "eth0"
                  "ranet.*"
                ];
              };

              bpf = std.mkOption {
                default = { };
                type = std.types.submodule {
                  freeformType = toml.type;

                  options = {
                    sample_rate = std.mkOption {
                      type = std.types.ints.positive;
                      default = 100;
                      description = "Sample 1 in N packets for flow events.";
                    };

                    ring_buf_size = std.mkOption {
                      type = std.types.ints.positive;
                      default = 262144;
                      description = "Ring buffer size in bytes.";
                    };

                    wakeup_batch = std.mkOption {
                      type = std.types.ints.positive;
                      default = 64;
                      description = "Send a ring buffer wakeup every N submitted flow events.";
                    };

                    iface_stats_size = std.mkOption {
                      type = std.types.ints.unsigned;
                      default = 0;
                      description = "Override the BPF iface stats map capacity, 0 means auto-compute from interface count.";
                    };

                    adaptive_sampling = std.mkOption {
                      type = std.types.bool;
                      default = false;
                      description = "Raise the sample rate while the ring buffer drops events and relax it afterwards.";
                    };

                    max_sample_rate = std.mkOption {
                      type = std.types.ints.positive;
                      default = 1000;
                      description = "Upper bound for the adaptive sample rate.";
                    };

                    pin_path = std.mkOption {
                      type = std.types.str;
                      default = "/sys/fs/bpf/rfm";
                      description = "bpffs directory that keeps the interface counters across restarts, empty keeps them private to the process.";
                    };
                  };
                };
              };

              collector = std.mkOption {
                default = { };
                type = std.types.submodule {
                  freeformType = toml.type;

                  options = {
                    max_flows = std.mkOption {
                      type = std.types.ints.unsigned;
                      default = 65536;
                      description = "Maximum number of active flows.";
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
                  freeformType = toml.type;

                  options = {
                    host = std.mkOption {
                      type = std.types.str;
                      default = "";
                      description = "IPFIX collector host.";
                    };

                    port = std.mkOption {
                      type = std.types.ints.between 0 65535;
                      default = 0;
                      description = "IPFIX collector UDP port.";
                    };

                    bind = std.mkOption {
                      default = { };
                      type = std.types.submodule {
                        freeformType = toml.type;

                        options = {
                          host = std.mkOption {
                            type = std.types.str;
                            default = "";
                            description = "IPFIX exporter local source address.";
                          };

                          port = std.mkOption {
                            type = std.types.ints.between 0 65535;
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

                    queue_size = std.mkOption {
                      type = std.types.ints.unsigned;
                      default = 0;
                      description = "Records that may wait for the IPFIX sender before new ones are dropped, 0 means max_flows or 4096, whichever is larger.";
                    };

                    flush_interval = std.mkOption {
                      type = std.types.str;
                      default = "1s";
                      description = "How long the IPFIX sender gathers records before sending a partial message (Go duration).";
                    };

                    max_message_size = std.mkOption {
                      type = std.types.ints.between 128 65535;
                      default = 1200;
                      description = "Largest IPFIX message in bytes, keep it under the path MTU.";
                    };
                  };
                };
              };

              prometheus = std.mkOption {
                default = { };
                type = std.types.submodule {
                  freeformType = toml.type;

                  options = {
                    host = std.mkOption {
                      type = std.types.str;
                      default = "::1";
                      description = "Prometheus metrics listen address.";
                    };

                    port = std.mkOption {
                      type = std.types.port;
                      default = 9669;
                      description = "Prometheus metrics listen port.";
                    };
                  };
                };
              };

              control = std.mkOption {
                default = { };
                type = std.types.submodule {
                  freeformType = toml.type;

                  options = {
                    socket = std.mkOption {
                      type = std.types.str;
                      default = "/run/rfm/rfm.sock";
                      description = "Unix socket the rfm command line talks to, empty disables it.";
                    };
                  };
                };
              };

              enrich = std.mkOption {
                default = { };
                type = std.types.submodule {
                  freeformType = toml.type;

                  options = {
                    mmdb = std.mkOption {
                      default = { };
                      type = std.types.submodule {
                        freeformType = toml.type;

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
                        freeformType = toml.type;

                        options = {
                          bmp = std.mkOption {
                            default = { };
                            type = std.types.submodule {
                              freeformType = toml.type;

                              options = {
                                host = std.mkOption {
                                  type = std.types.str;
                                  default = "";
                                  description = "BMP listen host for live RIB updates.";
                                };

                                port = std.mkOption {
                                  type = std.types.ints.between 0 65535;
                                  default = 0;
                                  description = "BMP listen port for live RIB updates.";
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

    # the agent runs as its own user with just the three capabilities the
    # bpf verifier, tcx attach and map access need, root is not required
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
      serviceConfig = {
        # systemd mounts bpffs with mode 0700, which the agent's user cannot
        # traverse, so the mount root is opened to 0711 (traverse only) and
        # the pin directory prepared as root before the agent drops to its
        # own user, pinned objects keep their own 0600 mode
        ExecStartPre = std.optionals (cfg.settings.agent.bpf.pin_path != "") [
          "+${pkgs.coreutils}/bin/chmod 0711 ${std.dirOf cfg.settings.agent.bpf.pin_path}"
          "+${pkgs.coreutils}/bin/install -d -m 0750 -o rfm -g rfm ${cfg.settings.agent.bpf.pin_path}"
        ];
        ExecStart = "${cfg.package}/bin/rfm agent -c ${configFile}";
        Restart = "on-failure";
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

        # the tree is read only except the runtime directory, the pin
        # directory lives under /sys which strict mode leaves writable
        ProtectSystem = "strict";
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
        # unix for the control socket, inet for ipfix, bmp and metrics,
        # netlink for interface discovery
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
