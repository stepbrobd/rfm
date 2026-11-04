//go:build linux

package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// ringProducer builds a program that writes one 64 byte record to events per
// run, mark in its first 8 bytes and zeros after
func ringProducer(tb testing.TB, events *ebpf.Map, mark int32) *ebpf.Program {
	tb.Helper()

	insns := asm.Instructions{asm.Mov.Imm(asm.R1, 0)}
	for off := int16(-56); off < 0; off += 8 {
		insns = append(insns, asm.StoreMem(asm.RFP, off, asm.R1, asm.DWord))
	}
	insns = append(insns,
		asm.Mov.Imm(asm.R1, mark),
		asm.StoreMem(asm.RFP, -64, asm.R1, asm.DWord),
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
		tb.Fatal(err)
	}
	tb.Cleanup(func() { prog.Close() })
	return prog
}

// BenchmarkRingReader times ReadRawEvent per record written to the first of several rings
func BenchmarkRingReader(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("requires root privileges")
	}

	for _, n := range []int{1, 4} {
		b.Run(fmt.Sprintf("rings=%d", n), func(b *testing.B) {
			rings := make([]*ebpf.Map, n)
			for i := range rings {
				ring, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 1 << 22})
				if err != nil {
					b.Fatal(err)
				}
				defer ring.Close()
				rings[i] = ring
			}
			drops, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 1})
			if err != nil {
				b.Fatal(err)
			}
			defer drops.Close()
			prog := ringProducer(b, rings[0], 0)
			rd, err := NewReader(rings, drops)
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
		})
	}
}

// BenchmarkRingReaderSparse times ReadRawEvent per record when 8 of 64 rings hold 4 records each, as for a reader that keeps up with the CPUs a NIC interrupts
func BenchmarkRingReaderSparse(b *testing.B) {
	if os.Geteuid() != 0 {
		b.Skip("requires root privileges")
	}

	const n, live, depth = 64, 8, 4
	rings := make([]*ebpf.Map, n)
	for i := range rings {
		ring, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 1 << 16})
		if err != nil {
			b.Fatal(err)
		}
		defer ring.Close()
		rings[i] = ring
	}
	drops, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		b.Fatal(err)
	}
	defer drops.Close()
	var progs []*ebpf.Program
	for i := 0; i < n; i += n / live {
		progs = append(progs, ringProducer(b, rings[i], int32(i)))
	}
	rd, err := NewReader(rings, drops)
	if err != nil {
		b.Fatal(err)
	}
	defer rd.Close()

	frame := make([]byte, 64)
	b.ResetTimer()
	for left := b.N; left > 0; left -= live * depth {
		b.StopTimer()
		for _, prog := range progs {
			if _, err := prog.Run(&ebpf.RunOptions{Data: frame, Repeat: depth}); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()
		for range live * depth {
			if _, err := rd.ReadRawEvent(); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// testRings returns n rings of 64 KiB, a drop counter and a reader over them
func testRings(t *testing.T, n int) ([]*ebpf.Map, Reader) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}
	var rings []*ebpf.Map
	for range n {
		ring, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 1 << 16})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ring.Close() })
		rings = append(rings, ring)
	}
	drops, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { drops.Close() })
	rd, err := NewReader(rings, drops)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rd.Close() })
	return rings, rd
}

// produce writes n records marked mark to ring
func produce(t *testing.T, ring *ebpf.Map, mark int32, n uint32) {
	t.Helper()

	prog := ringProducer(t, ring, mark)
	if _, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: n}); err != nil {
		t.Fatal(err)
	}
}

func TestRingReaderTakesTurnsAcrossRings(t *testing.T) {
	rings, rd := testRings(t, 3)
	produce(t, rings[0], 1, 100)
	produce(t, rings[2], 3, 2)

	// a ring gives at most readBatch records in a row, then the next ring with records has its turn
	rd.SetDeadline(time.Now())
	var marks []uint64
	for {
		raw, err := rd.ReadRawEvent()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		marks = append(marks, binary.NativeEndian.Uint64(raw))
	}
	if len(marks) != 102 {
		t.Fatalf("read %d records, want the 102 written", len(marks))
	}
	if turn := slices.Index(marks, 3); turn != readBatch || marks[turn+1] != 3 || marks[turn+2] != 1 {
		t.Fatalf("marks %v, want %d of the first ring, both of the third, then the rest of the first", marks, readBatch)
	}
}

func TestRingReaderReadsAcrossTheRingEnd(t *testing.T) {
	rings, rd := testRings(t, 1)

	// 800 records of 72 bytes per round wrap the 64 KiB ring in the second round, one record across its end
	rd.SetDeadline(time.Now())
	for round := range 5 {
		produce(t, rings[0], int32(round), 800)
		for i := range 800 {
			raw, err := rd.ReadRawEvent()
			if err != nil {
				t.Fatalf("round %d record %d: %v", round, i, err)
			}
			if mark := binary.NativeEndian.Uint64(raw); len(raw) != 64 || mark != uint64(round) {
				t.Fatalf("round %d record %d: %d bytes marked %d, want 64 marked %d", round, i, len(raw), mark, round)
			}
		}
		if _, err := rd.ReadRawEvent(); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("round %d: read past the records = %v, want the deadline", round, err)
		}
	}
}

func TestRingReaderSkipsDiscardedRecords(t *testing.T) {
	rings, rd := testRings(t, 1)

	// reserve then discard a record, which leaves a header with the discard bit in the ring
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, rings[0].FD()),
			asm.Mov.Imm(asm.R2, 64),
			asm.Mov.Imm(asm.R3, 0),
			asm.FnRingbufReserve.Call(),
			asm.JEq.Imm(asm.R0, 0, "out"),
			asm.Mov.Reg(asm.R1, asm.R0),
			asm.Mov.Imm(asm.R2, 0),
			asm.FnRingbufDiscard.Call(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("out"),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	if _, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 3}); err != nil {
		t.Fatal(err)
	}
	produce(t, rings[0], 7, 1)

	rd.SetDeadline(time.Now())
	raw, err := rd.ReadRawEvent()
	if err != nil {
		t.Fatal(err)
	}
	if mark := binary.NativeEndian.Uint64(raw); mark != 7 {
		t.Fatalf("mark = %d, want 7 past the discarded records", mark)
	}
	if _, err := rd.ReadRawEvent(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past the records = %v, want the deadline", err)
	}
}

func TestRingReaderWaitsForAnyRing(t *testing.T) {
	rings, rd := testRings(t, 4)

	// with every ring empty the read waits out its deadline
	start := time.Now()
	rd.SetDeadline(start.Add(50 * time.Millisecond))
	if _, err := rd.ReadRawEvent(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read of empty rings = %v, want the deadline", err)
	}
	if waited := time.Since(start); waited < 50*time.Millisecond {
		t.Fatalf("read of empty rings returned after %v, before its deadline", waited)
	}

	// a record in any ring ends the wait
	prog := ringProducer(t, rings[3], 4)
	produced := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, err := prog.Run(&ebpf.RunOptions{Data: make([]byte, 64)})
		produced <- err
	}()
	start = time.Now()
	rd.SetDeadline(start.Add(5 * time.Second))
	raw, err := rd.ReadRawEvent()
	if perr := <-produced; perr != nil {
		t.Fatal(perr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if mark := binary.NativeEndian.Uint64(raw); mark != 4 {
		t.Fatalf("mark = %d, want 4", mark)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("read returned %v after the record was written", waited)
	}
}
