{ std, inputs, ... }:

{ config, pkgs, ... }:

let
  cfg = config.services.rfm;

  toml = pkgs.formats.toml { };
in
{
  options.services.rfm = {
    enable = std.mkEnableOption "rfm";

    package = std.mkPackageOption inputs.self.packages.${pkgs.stdenv.hostPlatform.system} "default" { };

    settings = std.mkOption {
      type = std.types.submodule { freeformType = toml.type; };
      default = { };
      description = "settings for rfm";
    };
  };

  config = std.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
  };
}
