{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-ipfix";

  # enableDebugHook = true;
  inherit (common) interactive;

  nodes = { inherit (common) machine1 machine2; };

  testScript = ''
    import json
    import time

    def json_lines(machine, path: str) -> list[dict]:
      raw = machine.succeed(f"test -s {path} && cat {path}")
      return [json.loads(line) for line in raw.splitlines() if line.strip()]

    start_all()
    for m in [machine1, machine2]:
      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)

    machine1.succeed("nohup python3 ${./lib/ipfix_listener.py} </dev/null >/tmp/ipfix.out 2>/tmp/ipfix.err &")
    machine1.wait_until_succeeds("test -s /tmp/ipfix.ready")

    # generate TCP and UDP traffic so evicted flows are exported
    machine2.succeed("iperf3 -s -D -p 5201")
    time.sleep(1)

    machine1.succeed("iperf3 -c 192.168.1.2 -p 5201 -t 2 -P 1")
    time.sleep(2)

    machine1.succeed("iperf3 -c 192.168.1.2 -p 5201 -u -t 2 -b 10M")
    time.sleep(2)

    # ipfix export
    machine1.wait_until_succeeds(r"""grep -qE '"set_ids": \[([0-9]+, )*256[],]' /tmp/ipfix.jsonl""")
    # the sequence number counts the data records sent before a message
    machine1.wait_until_succeeds(r"""grep -qE '"sequence_num": ([2-9]|[1-9][0-9]+),' /tmp/ipfix.jsonl""")
    packets = json_lines(machine1, "/tmp/ipfix.jsonl")
    assert any(
      packet.get("version") == 10
      and packet.get("observation_domain_id") == 1
      and 2 in packet.get("set_ids", [])
      for packet in packets
    ), f"missing ipfix template packet in {packets}"
  '';
}
