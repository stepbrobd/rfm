{
  lib,
  mkShell,
  bear,
  bpftools,
  deno,
  go,
  go-tools,
  gomod2nix,
  gopls,
  libbpf,
  llvmPackages,
  pkg-config,
  python3,
  stdenv,
}:

mkShell {
  packages = [
    bear
    deno
    go
    go-tools
    gomod2nix
    gopls
    llvmPackages.clang-tools
    llvmPackages.clang-unwrapped
    llvmPackages.libllvm
    pkg-config
    python3
  ]
  ++ lib.optionals stdenv.isLinux [
    bpftools
    libbpf
  ];
}
