{
  lib,
  buildGoModule,
  fetchFromGitHub,
}:

buildGoModule (finalAttrs: {
  __structuredAttrs = true;

  pname = "netobserv-ebpf-agent";
  version = "2.0.2";

  src = fetchFromGitHub {
    owner = "netobserv";
    repo = "netobserv-ebpf-agent";
    tag = "v${finalAttrs.version}-community";
    hash = "sha256-X+KQG2zBkrWjGnX1CHDV3P0L2zpZX/bfmdq+l29LYFI=";
  };

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
