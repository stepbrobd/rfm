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
            overlays = [ inputs.gomod2nix.overlays.default ];
          };

          packages.default = pkgs.buildGoApplication {
            pname = "rfm";
            version = "0.0.1";
            src = ./.;
            modules = ./gomod2nix.toml;
            subPackages = [ "cmd/rfm" ];
          };

          devShells.default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                bear
                go
                go-tools
                gomod2nix
                gopls
                llvmPackages.clang-tools
                llvmPackages.clang-unwrapped
                llvmPackages.libllvm
                pkg-config
              ]
              ++ lib.optionals stdenv.isLinux [
                bpftools
                libbpf
              ];
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

            ${lib.getExe pkgs.deno} fmt readme.md
            ${lib.getExe pkgs.findutils} . -regex '.*\.\(c\|h\)' -exec ${lib.getExe' pkgs.llvmPackages.clang-tools "clang-format"} -style=LLVM -i {} \;
            ${lib.getExe pkgs.go} fix ./...
            ${lib.getExe pkgs.go} fmt ./...
            ${lib.getExe pkgs.go} mod tidy
            ${lib.getExe pkgs.go} test -race ./...
            ${lib.getExe pkgs.go} vet ./...
            ${lib.getExe pkgs.nixfmt-tree} .
            ${lib.getExe pkgs.taplo} format **/*.toml
            ${lib.getExe' pkgs.go-tools "staticcheck"} ./...
            ${lib.getExe' pkgs.gomod2nix "gomod2nix"}

            popd
          '';
        };
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
