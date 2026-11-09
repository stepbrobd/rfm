{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-cpus";

  inherit (common) interactive;

  nodes = {
    inherit (common) machine2;

    # four possible CPUs, one brought up at boot, like a VM with hotplug slots,
    # named so the test driver's address for it is the one it sets
    machine1 = {
      imports = [ (common.mkBase "192.168.1.1") ];

      virtualisation.cores = 4;
      boot.kernelParams = [ "maxcpus=1" ];

      services.rfm = {
        enable = true;
        settings.agent = {
          interfaces = [ "eth1" ];
          bpf.sample_rate = 1;
          # a flow reaches the metrics when it ends, a second after its last echo request
          collector.eviction_timeout = "1s";
          prometheus.port = 9669;
        };
      };
    };
  };

  testScript = common.helpers + ''
    def rings(m) -> int:
      return int(m.succeed("bpftool map show | grep -c ' ringbuf ' || true").strip())

    def wait_rings(m, n: int) -> None:
      deadline = time.time() + 10
      while rings(m) != n:
        assert time.time() < deadline, f"{rings(m)} ring buffers, want {n}"
        time.sleep(0.5)

    def drops(m) -> float:
      return sum(require_metric(m.succeed("curl -sf http://localhost:9669/metrics"), "rfm_collector_dropped_events_total"))

    def ping_on(m, cpu: int, n: int) -> None:
      """n echo requests sent from cpu, whose egress program runs on it, counted in rfm's ICMP egress flows."""
      before = sum(metric_values(m.succeed("curl -sf http://localhost:9669/metrics"), "rfm_flow_packets_total", ifname="eth1", direction="egress", proto="1"))
      m.succeed(f"taskset -c {cpu} ping -c {n} -i 0.05 -q 192.168.1.2")
      deadline = time.time() + 15
      while True:
        metrics = m.succeed("curl -sf http://localhost:9669/metrics")
        got = sum(metric_values(metrics, "rfm_flow_packets_total", ifname="eth1", direction="egress", proto="1")) - before
        if got >= n:
          break
        assert time.time() < deadline, f"rfm counted {got} of {n} echo requests sent from cpu {cpu}"
        time.sleep(1)

    start_all()
    for m in [machine1, machine2]:
      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)

    assert machine1.succeed("cat /sys/devices/system/cpu/possible").strip() == "0-3"
    assert machine1.succeed("cat /sys/devices/system/cpu/online").strip() == "0"

    # one ring for the one online CPU, not one per possible CPU
    wait_rings(machine1, 1)
    ping_on(machine1, 0, 20)

    # a CPU brought online gets its ring and its events reach the flows
    machine1.succeed("echo 1 > /sys/devices/system/cpu/cpu2/online")
    wait_rings(machine1, 2)
    machine1.wait_until_succeeds("journalctl -u rfm | grep 'event ring of a CPU that came online' | grep 'cpu=2'", timeout=10)
    # an event of cpu 2 before its ring was in place counts as a drop, none after
    dropped = drops(machine1)
    ping_on(machine1, 2, 20)

    # a CPU taken offline keeps its ring for when it comes back
    machine1.succeed("echo 0 > /sys/devices/system/cpu/cpu2/online")
    time.sleep(2)
    assert rings(machine1) == 2, f"{rings(machine1)} ring buffers after cpu 2 went offline, want 2"
    machine1.succeed("echo 1 > /sys/devices/system/cpu/cpu2/online")
    time.sleep(2)
    assert rings(machine1) == 2, f"{rings(machine1)} ring buffers after cpu 2 came back, want 2"
    ping_on(machine1, 2, 20)

    assert drops(machine1) == dropped, f"{drops(machine1) - dropped} events dropped with every online CPU on its ring"
    metrics = machine1.succeed("curl -sf http://localhost:9669/metrics")
    errors = metric_values(metrics, "rfm_errors_total", subsystem="bpf_map")
    assert sum(errors) == 0, f"bpf_map errors: {errors}"
  '';
}
