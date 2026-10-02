{
  lib,
  buildGoApplication,
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
          # code
          ./bpf
          ./cmd
          ./collector
          ./config
          ./ctl
          ./enrich
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

    # the default check hook takes its package list from subPackages, which
    # would test cmd/rfm alone, so every package is tested here and the
    # tests that need root skip themselves in the sandbox
    checkPhase = ''
      runHook preCheck
      go test -p "$NIX_BUILD_CORES" ./...
      runHook postCheck
    '';

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
