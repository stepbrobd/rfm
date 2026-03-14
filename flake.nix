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
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            config.allowDeprecatedx86_64Darwin = true;
          };

          formatter = pkgs.writeShellScriptBin "formatter" ''
            set -eoux pipefail
            shopt -s globstar

            root="$PWD"
            while [[ ! -f "$root/.git/index" ]]; do
              if [[ "$root" == "/" ]]; then
                exit 1
              fi
              root="$(dirname "$root")"
            done
            pushd "$root" > /dev/null

            ${lib.getExe pkgs.findutils} . -regex '.*\.\(c\|h\)' -exec ${lib.getExe' pkgs.clang-tools "clang-format"} -style=LLVM -i {} \;
            ${lib.getExe pkgs.nixfmt-tree} .

            popd
          '';
        };
    };

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  inputs.systems.url = "github:nix-systems/default";
  inputs.parts.url = "github:hercules-ci/flake-parts";
  inputs.parts.inputs.nixpkgs-lib.follows = "nixpkgs";
}
