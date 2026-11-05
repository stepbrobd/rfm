{
  lib,
  writeShellScriptBin,
  buildGoLatestModule,
  deno,
  git,
  go_latest,
  go-tools,
  gomod2nix,
  llvmPackages,
  nixfmt-tree,
  nufmt,
  ruff,
  stdenv,
  taplo,
  ty,
}:

let
  staticcheck = go-tools.override { buildGoModule = buildGoLatestModule; };
in
writeShellScriptBin "formatter" ''
  set -eoux pipefail
  pushd "$(${lib.getExe git} rev-parse --show-toplevel)" > /dev/null
  shopt -s globstar
  export PATH=${
    lib.makeBinPath [
      go_latest
      stdenv.cc
    ]
  }:$PATH

  ${lib.getExe deno} fmt .
  ${lib.getExe nixfmt-tree} .
  ${lib.getExe nufmt} **/*.nu
  ${lib.getExe taplo} format **/*.toml

  ${lib.getExe ruff} check --fix --unsafe-fixes --preview .
  ${lib.getExe ty} check --fix --error all .

  ${lib.getExe go_latest} fix ./...
  ${lib.getExe go_latest} fmt ./...
  ${lib.getExe go_latest} mod tidy
  ${lib.optionalString stdenv.hostPlatform.isLinux ''
    ${lib.getExe go_latest} test -race ./...
  ''}
  ${lib.getExe go_latest} vet ./...
  ${lib.optionalString stdenv.hostPlatform.isLinux ''
    ${lib.getExe' staticcheck "staticcheck"} ./...
  ''}
  ${lib.getExe' gomod2nix "gomod2nix"}

  ${lib.getExe' llvmPackages.clang-tools "clang-format"} -i $(${lib.getExe git} ls-files '*.c' '*.h' ':!bpf/include/vmlinux')

  popd
''
