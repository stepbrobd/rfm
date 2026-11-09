#!/usr/bin/env python3
# on the dut: decodes the sflow v5 flow samples hsflowd sends to 127.0.0.1:6343, one json line per sample with its receive time, used by measure.nu --counts
import json
import socket
import struct
import sys
import time

with open(sys.argv[1], "w") as out:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 6343))
    while True:
        d, _ = s.recvfrom(65535)
        t = time.time()
        try:
            o = 0
            _, at = struct.unpack_from(">II", d, o)
            o += 8 + (4 if at == 1 else 16)
            _, _, _, ns = struct.unpack_from(">IIII", d, o)
            o += 16
            for _ in range(ns):
                fmt, ln = struct.unpack_from(">II", d, o)
                o += 8
                end = o + ln
                if fmt in (1, 3):
                    if fmt == 1:
                        _, src, rate, pool, drops, inp, outp, nr = struct.unpack_from(">8I", d, o)
                        p = o + 32
                    else:
                        _, st, si, rate, pool, drops, _, inp, _, outp, nr = struct.unpack_from(">11I", d, o)
                        p = o + 44
                        src = st << 24 | si
                    flen = 0
                    for _ in range(nr):
                        rf, rl = struct.unpack_from(">II", d, p)
                        # a raw packet header record carries the length of the frame it was cut from
                        if rf == 1:
                            flen = struct.unpack_from(">4I", d, p + 8)[1]
                        p += 8 + rl
                    out.write(json.dumps({"t": t, "src": src, "rate": rate, "pool": pool, "drops": drops, "in": inp, "out": outp, "flen": flen}) + "\n")
                o = end
        except struct.error as e:
            out.write(json.dumps({"t": t, "error": str(e), "len": len(d)}) + "\n")
        out.flush()
