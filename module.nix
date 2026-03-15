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

              prometheus = std.mkOption {
                default = { };
                type = std.types.submodule {
                  freeformType = toml.type;

                  options = {
                    host = std.mkOption {
                      type = std.types.str;
                      default = "::";
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
