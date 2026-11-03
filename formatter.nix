{
  lib,
  writeShellScriptBin,
  deno,
  git,
  go,
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

writeShellScriptBin "formatter" ''
  set -eoux pipefail
  pushd "$(${lib.getExe git} rev-parse --show-toplevel)" > /dev/null
  shopt -s globstar
  export PATH=${
    lib.makeBinPath [
      go
      stdenv.cc
    ]
  }:$PATH

  ${lib.getExe deno} fmt .
  ${lib.getExe nixfmt-tree} .
  ${lib.getExe nufmt} **/*.nu
  ${lib.getExe taplo} format **/*.toml

  ${lib.getExe ruff} check --fix --unsafe-fixes --preview .
  ${lib.getExe ty} check --fix --error all .

  ${lib.getExe go} fix ./...
  ${lib.getExe go} fmt ./...
  ${lib.getExe go} mod tidy
  ${lib.getExe go} test -race ./...
  ${lib.getExe go} vet ./...
  ${lib.getExe' go-tools "staticcheck"} ./...
  ${lib.getExe' gomod2nix "gomod2nix"}

  ${lib.getExe' llvmPackages.clang-tools "clang-format"} -i $(${lib.getExe git} ls-files '*.c' '*.h' ':!bpf/include/vmlinux')

  popd
''
