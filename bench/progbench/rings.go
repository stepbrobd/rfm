//go:build linux

package main

import (
	"errors"
	"math/bits"
	"os"

	"github.com/cilium/ebpf"
)

// an agent object writes its events to one ring per CPU held in
// rfm_flow_rings, older objects and the variants to the single
// rfm_flow_events

// sizeRings sizes the single ring to 1 << order bytes before the collection
// loads, and gives rfm_flow_rings a slot per possible CPU
func sizeRings(spec *ebpf.CollectionSpec, order uint32) {
	if m, ok := spec.Maps["rfm_flow_events"]; ok {
		m.MaxEntries = 1 << order
	}
	if m, ok := spec.Maps["rfm_flow_rings"]; ok {
		m.MaxEntries = uint32(ebpf.MustPossibleCPU())
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
