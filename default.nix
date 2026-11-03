{
  lib,
  buildGoApplication,
  goflow2,
  installShellFiles,
  versionCheckHook,
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
          ./bpf
          ./cmd
          ./collector
          ./config
          ./ctl
          ./enrich
          ./export
          ./probe
          ./testutil
          ./go.mod
          ./go.sum
          ./gomod2nix.toml
          ./version.txt
        ];
      };

    modules = ./gomod2nix.toml;

    subPackages = [ "cmd/rfm" ];

    checkPhase = ''
      runHook preCheck
      go test -p "$NIX_BUILD_CORES" ./...
      runHook postCheck
    '';

    nativeCheckInputs = [ goflow2 ];

    CGO_ENABLED = 0;

    ldflags = [
      "-s"
      "-w"
      "-X"
      "main.version=${finalAttrs.version}"
    ];

    nativeBuildInputs = [ installShellFiles ];

    postInstall = ''
      for shell in bash zsh fish; do
        installShellCompletion --cmd ${finalAttrs.pname} --''${shell} <("$out/bin/${finalAttrs.pname}" completion "$shell")
      done
    '';

    doInstallCheck = true;
    nativeInstallCheckInputs = [ versionCheckHook ];
    versionCheckProgramArg = "version";
  })
)
