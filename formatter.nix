{
  lib,
  writeShellScriptBin,
  deno,
  findutils,
  go,
  go-tools,
  gomod2nix,
  llvmPackages,
  nixfmt-tree,
  taplo,
}:

writeShellScriptBin "formatter" ''
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

  ${lib.getExe deno} fmt readme.md grafana/dashboard.json
  ${lib.getExe nixfmt-tree} .
  ${lib.getExe taplo} format **/*.toml

  ${lib.getExe go} fix ./...
  ${lib.getExe go} fmt ./...
  ${lib.getExe go} generate ./...
  ${lib.getExe go} mod tidy
  ${lib.getExe go} test -race ./...
  ${lib.getExe go} vet ./...
  ${lib.getExe' go-tools "staticcheck"} ./...
  ${lib.getExe' gomod2nix "gomod2nix"}

  ${lib.getExe findutils} . -regex '.*\.\(c\|h\)' -exec ${lib.getExe' llvmPackages.clang-tools "clang-format"} -i {} \;

  popd
''
