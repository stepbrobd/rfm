{
  lib,
  stdenv,
  fetchFromGitHub,
  clang,
  llvmPackages,
  bpftools,
  libbpf,
  elfutils,
  zlib,
  linuxHeaders,
}:

stdenv.mkDerivation (finalAttrs: {
  __structuredAttrs = true;

  pname = "hsflowd";
  version = "2.1.26-1";

  src = fetchFromGitHub {
    owner = "sflow";
    repo = "host-sflow";
    tag = "v${finalAttrs.version}";
    hash = "sha256-WvTozKsxAdMvcIYF3up3yNspDQwxbO8Cb/vIuvZmJFE=";
  };

  dontConfigure = true;

  env.FEATURES = lib.concatStringsSep " " [
    "EPCAP" # eBPF/TCX sampling
    "PSAMPLE" # kernel psample
  ];

  enableParallelBuilding = true;

  nativeBuildInputs = [
    clang
    bpftools
  ];

  buildInputs = [
    libbpf
    elfutils
    zlib
  ];

  hardeningDisable = [ "all" ];

  postPatch = ''
    substituteInPlace src/Linux/Makefile \
      --replace-fail '$(CLANG) -target bpf -g -O2' \
        '${lib.getExe' llvmPackages.clang-unwrapped "clang"} -target bpf -g -O2 -I${lib.getDev libbpf}/include -I${linuxHeaders}/include' \
      --replace-fail '-I/usr/include/bpf' '-I${lib.getDev libbpf}/include' \
      --replace-fail 'mod_epcap.o: mod_epcap.c $(HEADERS)' \
        'mod_epcap.o: mod_epcap.c sample.skel.h $(HEADERS)'
  '';

  installFlags = [
    "INSTROOT=${placeholder "out"}"
    "BINDIR=/bin"
    "CONFDIR=/etc"
    "MODDIR=/lib/hsflowd/modules"
  ];

  meta = {
    homepage = "https://github.com/sflow/host-sflow";
    mainProgram = "hsflowd";
    platforms = lib.platforms.linux;
  };
})
