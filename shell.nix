{
  lib,
  mkShell,
  bear,
  bpftools,
  go,
  go-tools,
  gomod2nix,
  gopls,
  libbpf,
  llvmPackages,
  pkg-config,
  stdenv,
}:

mkShell {
  packages = [
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
}
