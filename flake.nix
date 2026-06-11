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
              config.allowDeprecatedx86_64Darwin = true;
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
  };

  nixConfig = {
    extra-substituters = [ "https://cache.ysun.co" ];
    extra-trusted-public-keys = [ "cache.ysun.co-1:WxPYwT5g3kt9XhUhHPpNLZKI9HIOsVVAuqSHpok8Qt4=" ];
  };
}
