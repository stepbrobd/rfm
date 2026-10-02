{ inputs, std, ... }:

{ hostPkgs, ... }:

let
  common = import ./lib { inherit inputs std; };

  # whether the module takes these agent settings, evaluated on its own and
  # forced deeply, the nixos options it sets take no part in that
  accepts =
    agent:
    (std.tryEval (
      std.deepSeq
        (std.evalModules {
          modules = [
            inputs.self.nixosModules.default
            {
              _module.args.pkgs = hostPkgs;
              _module.check = false;
              services.rfm.settings.agent = {
                interfaces = [ "eth1" ];
              }
              // agent;
            }
          ];
        }).config.services.rfm.settings
        true
    )).success;

  # the defaults, zero ports as the fleet runs them, which keep ipfix and
  # bmp at their defaults or off and the ipfix source port ephemeral, other
  # names where the socket and the pin may live, and the lowest ports the
  # unit can bind next to a collector port below them, which it only sends to
  honored = [
    { }
    {
      control.socket = "";
      bpf.pin_path = "";
      ipfix = {
        host = "192.0.2.1";
        port = 2055;
        bind.port = 0;
      };
      enrich.rib.bmp.port = 0;
    }
    {
      control.socket = "/run/rfm/ctl.sock";
      bpf.pin_path = "/sys/fs/bpf/rfm-lab";
      prometheus.port = 65535;
    }
    {
      prometheus.port = 1024;
      ipfix = {
        host = "192.0.2.1";
        port = 1023;
        bind.port = 1024;
      };
      enrich.rib.bmp.port = 1024;
    }
  ];

  # a socket outside the runtime directory, a pin outside the bpffs mount
  # root, a misspelled key, a port the agent rejects and ports below 1024,
  # which the unit cannot bind without CAP_NET_BIND_SERVICE
  unhonored = [
    { control.socket = "/run/rfm.sock"; }
    { control.socket = "/run/rfm/ctl/rfm.sock"; }
    { bpf.pin_path = "/sys/fs/bpf/rfm/host"; }
    { bpf.pin_path = "/run/rfm/bpf"; }
    { bpf.sample_rte = 10; }
    { enrich.rib.bmp.prot = 11019; }
    { prometheus.port = 0; }
    { prometheus.port = 1023; }
    { enrich.rib.bmp.port = 1023; }
    {
      ipfix = {
        host = "192.0.2.1";
        bind.port = 1023;
      };
    }
  ];
in
{
  name = "rfm-lifecycle";

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  nodes = {
    inherit (common)
      machine1
      machine2
      machine3
      machine4
      ;

    # the asn database is written after boot, as geoipupdate's first run
    # waits for network-online.target and rfm does not
    machine5 =
      { pkgs, ... }:
      {
        imports = [ (common.mkBase "192.168.1.5") ];

        environment.etc."rfm-test-asn-db".text = "${pkgs.dbip-asn-lite}/share/dbip/dbip-asn-lite.mmdb";

        services.rfm = {
          enable = true;
          settings.agent = {
            interfaces = [ "eth1" ];
            enrich.mmdb.asn_db = "/var/lib/rfm-test/asn.mmdb";
          };
        };

        # restarts faster than the default limit of five starts in ten
        # seconds allows, which only a unit without a start limit survives
        systemd.services.rfm.serviceConfig.RestartSec = std.mkForce "100ms";
      };
  };

  testScript = common.helpers + ''
    from datetime import timedelta

    # the module refuses at evaluation what the hardened unit cannot honor,
    # rather than deploying a unit that fails at start
    refused = ${std.toJSON (map std.toJSON (std.filter (agent: !accepts agent) honored))}
    assert refused == [], f"module refuses settings the unit honors: {refused}"
    accepted = ${std.toJSON (map std.toJSON (std.filter accepts unhonored))}
    assert accepted == [], f"module accepts settings the unit cannot honor: {accepted}"

    start_all()
    machines = [machine1, machine2, machine3, machine4]

    # service lifecycle and basic checks
    for m in machines:
      m.wait_for_unit("multi-user.target")
      m.succeed("which rfm")
      m.succeed("ip -4 -br addr show dev eth1")

      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)
      m.succeed("curl -sf http://localhost:9669/metrics | grep rfm_")

    # health and error metrics
    for m in machines:
      metrics = m.succeed("curl -sf http://localhost:9669/metrics")
      require_metric(metrics, "rfm_collector_active_flows")
      require_metric(metrics, "rfm_collector_dropped_events_total")
      require_metric(metrics, "rfm_collector_forced_evictions_total")
      require_metric(metrics, "rfm_errors_total", subsystem="bpf_map")
      require_metric(metrics, "rfm_errors_total", subsystem="ipfix")
      require_metric(metrics, "rfm_errors_total", subsystem="ring_buffer")

    # the control socket answers the birdc style commands
    for m in machines:
      status = m.succeed("rfm status")
      assert "interfaces" in status and "eth1" in status, f"unexpected status output: {status}"
      assert "sampling" in status, f"unexpected status output: {status}"
      m.succeed("rfm flows count")
      m.succeed("rfm config show | grep -q interfaces")
      m.succeed("rfm set sample-rate 7")
      assert "1 in 7" in m.succeed("rfm status"), "sample rate change not visible in status"
      m.succeed("rfm status --json | grep -q '\"rate\": 7'")
      m.succeed("rfm set sample-rate 1")

    # a start that fails until a file shows up is retried for as long as it
    # fails, on machine5 well past the default limit of five starts in ten
    # seconds, and succeeds once the file exists
    machine5.wait_for_unit("multi-user.target")
    machine5.wait_until_succeeds('test "$(systemctl show -P NRestarts rfm.service)" -gt 20', timeout=timedelta(seconds=60))
    machine5.fail("systemctl is-active rfm.service")
    machine5.succeed('install -D -m 0644 "$(cat /etc/rfm-test-asn-db)" /var/lib/rfm-test/asn.mmdb')
    machine5.wait_until_succeeds("systemctl is-active rfm.service", timeout=timedelta(seconds=60))
    machine5.wait_for_open_port(9669)
  '';
}
