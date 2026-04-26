{ std, inputs, ... }:

{ config, pkgs, ... }:

let
  cfg = config.services.rfm;

  toml = pkgs.formats.toml { };

  configFile = toml.generate "rfm.toml" cfg.settings;
in
{
  options.services.rfm = {
    enable = std.mkEnableOption "rfm";

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
                  Network interfaces to monitor.
                  Use `["*"]` for all non-loopback interfaces.
                '';
                example = [
                  "eth0"
                  "tailscale0"
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
      description = "Settings for rfm, serialized to TOML.";
    };
  };

  config = std.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    systemd.services.rfm = {
      description = "rfm network flow monitor";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/rfm agent -c ${configFile}";
        Restart = "on-failure";
      };
    };
  };
}
