{
  lib,
  mkShell,
  bpftools,
  deno,
  go_latest,
  go-tools,
  goflow2,
  gomod2nix,
  gopls,
  libbpf,
  llvmPackages,
  nufmt,
  nushell,
  pkg-config,
  python3,
  stdenv,
}:

mkShell {
  packages = [
    deno
    go_latest
    go-tools
    goflow2
    gomod2nix
    gopls
    llvmPackages.clang-tools
    llvmPackages.clang-unwrapped
    llvmPackages.libllvm
    nufmt
    nushell
    pkg-config
    python3
  ]
  ++ lib.optionals stdenv.hostPlatform.isLinux [
    bpftools
    libbpf
  ];
}
