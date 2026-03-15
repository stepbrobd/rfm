{
  lib,
  buildGoApplication,
  installShellFiles,
}:

buildGoApplication (
  lib.fix (finalAttrs: {
    meta.mainProgram = finalAttrs.pname;
    pname = "rfm";
    version = lib.fileContents ./version.txt;

    src =
      with lib.fileset;
      toSource {
        root = ./.;
        fileset = unions [
          # code
          ./bpf
          ./cmd
          ./collector
          ./config
          ./export
          ./probe
          ./testutil
          # meta
          ./go.mod
          ./go.sum
          ./gomod2nix.toml
          ./version.txt
        ];
      };

    modules = ./gomod2nix.toml;

    subPackages = [ "cmd/rfm" ];

    ldflags = [
      "-X"
      "main.version=${finalAttrs.version}"
    ];

    nativeBuildInputs = [ installShellFiles ];

    postInstall = ''
      for shell in bash zsh fish; do
        installShellCompletion --cmd ${finalAttrs.pname} --''${shell} <("$out/bin/${finalAttrs.pname}" completion "$shell")
      done
    '';
  })
)
