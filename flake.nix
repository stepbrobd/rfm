{
  outputs =
    inputs:
    inputs.parts.lib.mkFlake { inherit inputs; } (
      { lib, ... }:
      let
        lift =
          func: path:
          func (
            lib.modules.importApply path {
              inherit inputs;
              std = builtins // lib;
            }
          );
      in
      {
        systems = import inputs.systems;

        flake.nixosModules.default = lift lib.id ./module.nix;

        perSystem =
          { pkgs, system, ... }:
          {
            _module.args.pkgs = import inputs.nixpkgs {
              inherit system;
              overlays = [ inputs.gomod2nix.overlays.default ];
            };

            checks =
              lib.genAttrs'
                (lib.filter (lib.hasSuffix ".nix") (
                  lib.map (f: ./integration/${f}) (lib.attrNames (lib.readDir ./integration))
                ))
                (
                  path:
                  lib.nameValuePair (lib.removeSuffix ".nix" (lib.baseNameOf path)) (
                    lift pkgs.testers.runNixOSTest path
                  )
                );

            devShells.default = pkgs.callPackage ./shell.nix { };

            formatter = pkgs.callPackage ./formatter.nix { };

            packages.default = pkgs.callPackage ./default.nix { };

            packages.hsflowd = pkgs.callPackage ./bench/hsflowd.nix { };
            packages.netobserv = pkgs.callPackage ./bench/netobserv.nix { };
            packages.bench =
              (lib.nixosSystem {
                inherit system;
                specialArgs = { inherit inputs; };
                modules = [
                  ./bench
                  inputs.g5k.nixosModules.g5k-image-systemd
                ];
              }).config.system.build.g5k-image;
          };
      }
    );

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable-small";
    systems.url = "github:nix-systems/triplet";
    parts.url = "github:hercules-ci/flake-parts";
    parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    utils.url = "github:numtide/flake-utils";
    utils.inputs.systems.follows = "systems";
    gomod2nix.url = "github:nix-community/gomod2nix";
    gomod2nix.inputs.nixpkgs.follows = "nixpkgs";
    gomod2nix.inputs.flake-utils.follows = "utils";
    g5k.url = "github:oar-team/nixos-g5k-image";
    g5k.inputs.nixpkgs.follows = "nixpkgs";
    g5k.inputs.kapack.follows = "";
  };

  nixConfig = {
    extra-substituters = [ "https://cache.ysun.co" ];
    extra-trusted-public-keys = [ "cache.ysun.co-1:WxPYwT5g3kt9XhUhHPpNLZKI9HIOsVVAuqSHpok8Qt4=" ];
  };
}
