{
  outputs =
    inputs:
    inputs.parts.lib.mkFlake { inherit inputs; } {
      systems = import inputs.systems;

      perSystem =
        {
          lib,
          pkgs,
          system,
          ...
        }:
        (lib.recursiveUpdate
          {
            _module.args.pkgs = import inputs.nixpkgs {
              inherit system;
              config.allowDeprecatedx86_64Darwin = true;
              overlays = [ inputs.gomod2nix.overlays.default ];
            };
          }
          (
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
              checks.default = lift pkgs.testers.runNixOSTest ./test.nix;
              devShells.default = pkgs.callPackage ./shell.nix { };
              formatter = pkgs.callPackage ./formatter.nix { };
              packages.default = pkgs.callPackage ./default.nix { };
            }
          )
        );
    };

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  inputs.systems.url = "github:nix-systems/default";
  inputs.parts.url = "github:hercules-ci/flake-parts";
  inputs.parts.inputs.nixpkgs-lib.follows = "nixpkgs";
  inputs.utils.url = "github:numtide/flake-utils";
  inputs.utils.inputs.systems.follows = "systems";
  inputs.gomod2nix.url = "github:nix-community/gomod2nix";
  inputs.gomod2nix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.gomod2nix.inputs.flake-utils.follows = "utils";
}
