//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

// an agent object writes its events to one ring per CPU held in
// rfm_flow_rings, older objects and the variants to the single
// rfm_flow_events

// eventSize is the size of struct rfm_flow_event, a record of the stage
// programs holds several back to back
const eventSize = 56

// stageMax is RFM_STAGE_MAX in bpf/rfm_common.h, the events the stage of a CPU holds
const stageMax = 32

// sizeRings sizes the single ring to 1 << order bytes before the collection
// loads, and gives rfm_flow_rings and the flush timers of the stages a slot
// per possible CPU
func sizeRings(spec *ebpf.CollectionSpec, order uint32) {
	if m, ok := spec.Maps["rfm_flow_events"]; ok {
		m.MaxEntries = 1 << order
	}
	for _, name := range []string{"rfm_flow_rings", "rfm_stage_timers"} {
		if m, ok := spec.Maps[name]; ok {
			m.MaxEntries = uint32(ebpf.MustPossibleCPU())
		}
	}
}

// setStage sets the events a stage program writes per record, the programs
// without a stage ignore it and an object without stage programs takes 1
func setStage(spec *ebpf.CollectionSpec, k uint32) error {
	v, ok := spec.Variables["rfm_stage_events"]
	if !ok {
		if k > 1 {
			return errors.New("the object has no stage programs")
		}
		return nil
	}
	if k < 1 || k > stageMax {
		return fmt.Errorf("a stage holds 1 to %d events, got %d", stageMax, k)
	}
	return v.Set(k)
}

// waitStages waits until the stage of every CPU is empty with no flush
// pending, the timer of a stage writes it 10 ms after the event that armed it
func waitStages(coll *ebpf.Collection) error {
	m, ok := coll.Maps["rfm_cpu_stage"]
	if !ok {
		return nil
	}
	stride := (int(m.ValueSize()) + 7) &^ 7
	for deadline := time.Now().Add(time.Second); ; {
		buf, err := m.LookupBytes(uint32(0))
		if err != nil {
			return err
		}
		idle := true
		// n and armed lead struct rfm_stage
		for off := 0; off+16 <= len(buf); off += stride {
			if binary.NativeEndian.Uint32(buf[off:]) != 0 || binary.NativeEndian.Uint64(buf[off+8:]) != 0 {
				idle = false
			}
		}
		if idle {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("a stage still holds events a second after the runs")
		}
		time.Sleep(time.Millisecond)
	}
}

// eventRings returns the rings of a loaded collection, creating the per-CPU
// rings of size(cpu) bytes and holding them in rfm_flow_rings, the caller
// closes the rings it returns, the single ring belongs to the collection
func eventRings(spec *ebpf.CollectionSpec, coll *ebpf.Collection, size func(cpu int) uint32) ([]*ebpf.Map, bool, error) {
	if m, ok := coll.Maps["rfm_flow_events"]; ok {
		return []*ebpf.Map{m}, false, nil
	}
	outer, ok := coll.Maps["rfm_flow_rings"]
	if !ok {
		return nil, false, errors.New("no rfm_flow_events or rfm_flow_rings map")
	}
	var rings []*ebpf.Map
	for cpu := range int(outer.MaxEntries()) {
		ms := spec.Maps["rfm_flow_rings"].InnerMap.Copy()
		ms.MaxEntries = size(cpu)
		ring, err := ebpf.NewMap(ms)
		if err == nil {
			rings = append(rings, ring)
			err = outer.Put(uint32(cpu), ring)
		}
		if err != nil {
			closeRings(rings)
			return nil, false, err
		}
	}
	return rings, true, nil
}

func closeRings(rings []*ebpf.Map) {
	for _, r := range rings {
		r.Close()
	}
}

// pinnedRing puts the whole ring of 1 << order bytes on the CPU test runs
// run on, and a page on every other CPU
func pinnedRing(order uint32) func(cpu int) uint32 {
	return func(cpu int) uint32 {
		if cpu == pinnedCPU {
			return 1 << order
		}
		return uint32(os.Getpagesize())
	}
}

// splitRing shares 1 << order bytes among the CPUs, rounded down to a power
// of two and at least a page each
func splitRing(order uint32) func(cpu int) uint32 {
	per := uint32(1<<order) / uint32(ebpf.MustPossibleCPU())
	per = max(uint32(1)<<(31-bits.LeadingZeros32(max(per, 1))), uint32(os.Getpagesize()))
	return func(int) uint32 { return per }
}
