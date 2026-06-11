{ inputs, std, ... }:

let
  common = import ./lib { inherit inputs std; };
in
{
  name = "rfm-ipfix";

  # enableDebugHook = true;
  interactive.sshBackdoor.enable = true;

  nodes = { inherit (common) machine1 machine2; };

  testScript = ''
    import base64
    import json
    import time

    def json_lines(machine, path: str) -> list[dict]:
      raw = machine.succeed(f"test -s {path} && cat {path}")
      return [json.loads(line) for line in raw.splitlines() if line.strip()]

    def start_ipfix_listener(machine) -> None:
      script = base64.b64encode(
        b"import json\n"
        b"import socket\n"
        b"import struct\n"
        b"\n"
        b"sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        b"sock.bind((\"127.0.0.1\", 4739))\n"
        b"with open(\"/tmp/ipfix.ready\", \"w\", encoding=\"utf-8\") as ready:\n"
        b"  ready.write(\"ready\\n\")\n"
        b"\n"
        b"with open(\"/tmp/ipfix.jsonl\", \"a\", encoding=\"utf-8\") as out:\n"
        b"  while True:\n"
        b"    data, _ = sock.recvfrom(65535)\n"
        b"    if len(data) < 16:\n"
        b"      continue\n"
        b"\n"
        b"    version, length, export_time, sequence_num, observation_domain_id = struct.unpack(\"!HHIII\", data[:16])\n"
        b"    set_ids = []\n"
        b"    offset = 16\n"
        b"    limit = min(length, len(data))\n"
        b"\n"
        b"    while offset + 4 <= limit:\n"
        b"      set_id, set_len = struct.unpack(\"!HH\", data[offset:offset + 4])\n"
        b"      if set_len < 4 or offset + set_len > limit:\n"
        b"        break\n"
        b"      set_ids.append(set_id)\n"
        b"      offset += set_len\n"
        b"\n"
        b"    out.write(\n"
        b"      json.dumps(\n"
        b"        {\n"
        b"          \"version\": version,\n"
        b"          \"length\": length,\n"
        b"          \"export_time\": export_time,\n"
        b"          \"sequence_num\": sequence_num,\n"
        b"          \"observation_domain_id\": observation_domain_id,\n"
        b"          \"set_ids\": set_ids,\n"
        b"        }\n"
        b"      )\n"
        b"      + \"\\n\"\n"
        b"    )\n"
        b"    out.flush()\n"
      ).decode()
      machine.succeed("rm -f /tmp/ipfix.ready /tmp/ipfix.jsonl /tmp/ipfix.out /tmp/ipfix.err /tmp/ipfix-listener.py")
      machine.succeed(
        f"printf '%s' '{script}' | base64 -d > /tmp/ipfix-listener.py"
      )
      machine.succeed("python3 -m py_compile /tmp/ipfix-listener.py")
      machine.succeed("nohup python3 /tmp/ipfix-listener.py </dev/null >/tmp/ipfix.out 2>/tmp/ipfix.err &")
      machine.wait_until_succeeds("test -s /tmp/ipfix.ready")

    start_all()
    for m in [machine1, machine2]:
      m.wait_for_unit("rfm.service")
      m.wait_for_open_port(9669)

    start_ipfix_listener(machine1)

    # generate TCP and UDP traffic so evicted flows are exported
    machine2.succeed("iperf3 -s -D -p 5201")
    time.sleep(1)

    machine1.succeed("iperf3 -c 192.168.1.2 -p 5201 -t 2 -P 1")
    time.sleep(2)

    machine1.succeed("iperf3 -c 192.168.1.2 -p 5201 -u -t 2 -b 10M")
    time.sleep(2)

    # ipfix export
    machine1.wait_until_succeeds("test -s /tmp/ipfix.jsonl")
    time.sleep(5)
    packets = json_lines(machine1, "/tmp/ipfix.jsonl")
    assert any(
      packet.get("version") == 10
      and packet.get("observation_domain_id") == 1
      and 2 in packet.get("set_ids", [])
      for packet in packets
    ), f"missing ipfix template packet in {packets}"
    assert any(
      packet.get("version") == 10
      and 256 in packet.get("set_ids", [])
      for packet in packets
    ), f"missing ipv4 ipfix data packet in {packets}"
    assert max((packet.get("sequence_num", -1) for packet in packets), default = -1) >= 1, (
      f"expected multiple ipfix data records in {packets}"
    )
  '';
}
