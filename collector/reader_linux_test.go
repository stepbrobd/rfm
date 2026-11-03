//go:build linux

package collector

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// ringProducer builds a program that writes one 64 byte record of zeros to
// events per run
func ringProducer(b *testing.B, events *ebpf.Map) *ebpf.Program {
	b.Helper()

	insns := asm.Instructions{asm.Mov.Imm(asm.R1, 0)}
	for off := int16(-64); off < 0; off += 8 {
		insns = append(insns, asm.StoreMem(asm.RFP, off, asm.R1, asm.DWord))
	}
	insns = append(insns,
		asm.LoadMapPtr(asm.R1, events.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -64),
		asm.Mov.Imm(asm.R3, 64),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SchedCLS,
		Instructions: insns,
		License:      "GPL",
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { prog.Close() })
	return prog
}

// BenchmarkRingReader times ReadRawEvent on records a test run wrote to a
// real ring buffer, one op is one record
func BenchmarkRingReader(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("requires root privileges")
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 1 << 22})
	if err != nil {
		b.Fatal(err)
	}
	defer events.Close()
	drops, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		b.Fatal(err)
	}
	defer drops.Close()
	prog := ringProducer(b, events)
	rd, err := NewReader(events, drops)
	if err != nil {
		b.Fatal(err)
	}
	defer rd.Close()

	// 32768 records of 72 bytes fit the 4 MiB ring
	const chunk = 1 << 15
	frame := make([]byte, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for left := b.N; left > 0; {
		n := min(left, chunk)
		b.StopTimer()
		if _, err := prog.Run(&ebpf.RunOptions{Data: frame, Repeat: uint32(n)}); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		for range n {
			if _, err := rd.ReadRawEvent(); err != nil {
				b.Fatal(err)
			}
		}
		left -= n
	}
}
