{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };

  kernels = [
    "linuxPackages_6_12"
    "linuxPackages_6_18"
    "linuxPackages_7_0"
    "linuxPackages_7_1"
  ];

  # "linuxPackages_7_0" -> "k70"
  nodeName = attr: "k" + std.replaceStrings [ "_" ] [ "" ] (std.removePrefix "linuxPackages_" attr);

  mkNode =
    attr:
    { pkgs, ... }:
    {
      imports = [ (common.mkBase "192.168.1.10") ];

      # the actual integetration test lesgoooo
      boot.kernelPackages = std.mkForce pkgs.${attr};

      services.rfm = {
        enable = true;
        settings.agent = {
          interfaces = [
            "eth1"
            "lo"
          ];
          bpf.sample_rate = 1;
          prometheus.port = 9669;
        };
      };
    };
in
{
  name = "rfm-versions";

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  nodes = std.listToAttrs (
    std.map (attr: {
      name = nodeName attr;
      value = mkNode attr;
    }) kernels
  );

  testScript = ''
    machines = [ ${std.concatStringsSep ", " (std.map nodeName kernels)} ]

    for m in machines:
      with subtest(m.name):
        m.start()
        m.wait_for_unit("multi-user.target")
        print(m.succeed("uname -r"))

        m.wait_for_unit("rfm.service")
        m.wait_for_open_port(9669)
        m.succeed("curl -sf http://localhost:9669/metrics | grep rfm_")

        m.succeed("bpftool net show | grep rfm_tc_ingress")
        m.succeed("bpftool net show | grep rfm_tc_egress")

        m.shutdown()
  '';
}
