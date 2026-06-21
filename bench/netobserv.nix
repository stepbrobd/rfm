{
  lib,
  buildGoModule,
  fetchFromGitHub,
}:

buildGoModule (finalAttrs: {
  __structuredAttrs = true;

  pname = "netobserv-ebpf-agent";
  version = "1.11.5";

  src = fetchFromGitHub {
    owner = "netobserv";
    repo = "netobserv-ebpf-agent";
    tag = "v${finalAttrs.version}-community";
    hash = "sha256-XuPMiBb1udd95wVMRtrh/988ucJhCn9L80VChemfL7Q=";
  };

  # use in-tree vendor as is
  vendorHash = null;

  env.CGO_ENABLED = 0;

  subPackages = [ "cmd" ];

  postInstall = ''
    mv "$out/bin/cmd" "$out/bin/netobserv-ebpf-agent"
  '';

  meta = {
    homepage = "https://github.com/netobserv/netobserv-ebpf-agent";
    mainProgram = "netobserv-ebpf-agent";
    platforms = lib.platforms.linux;
  };
})
