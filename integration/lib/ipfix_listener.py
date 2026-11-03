import json
import socket
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 4739))
with open("/tmp/ipfix.ready", "w", encoding="utf-8") as ready:
  ready.write("ready\n")

with open("/tmp/ipfix.jsonl", "a", encoding="utf-8") as out:
  while True:
    data, _ = sock.recvfrom(65535)
    if len(data) < 16:
      continue

    version, length, export_time, sequence_num, observation_domain_id = struct.unpack("!HHIII", data[:16])
    set_ids = []
    offset = 16
    limit = min(length, len(data))

    while offset + 4 <= limit:
      set_id, set_len = struct.unpack("!HH", data[offset:offset + 4])
      if set_len < 4 or offset + set_len > limit:
        break
      set_ids.append(set_id)
      offset += set_len

    out.write(
      json.dumps(
        {
          "version": version,
          "length": length,
          "export_time": export_time,
          "sequence_num": sequence_num,
          "observation_domain_id": observation_domain_id,
          "set_ids": set_ids,
        }
      )
      + "\n"
    )
    out.flush()
