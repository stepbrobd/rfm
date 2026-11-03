package probe

import "maps"

// ifaceFamilies is RFM_FAMILIES in bpf/rfm_common.h, the entries of a counter
// slot per direction: non-IP, IPv4 and IPv6
const ifaceFamilies = 3

// IfaceCounter is the traffic one interface carried in one direction and
// family, summed over CPUs and over the counter slot and the hash
type IfaceCounter struct {
	Ifindex uint32
	Dir     uint8
	// Proto is 4 for IPv4, 6 for IPv6 and 0 for everything else
	Proto   uint8
	Packets uint64
	Bytes   uint64
}

// familyProto is the proto of an IfaceCounter of family fam in a slot
func familyProto(fam int) uint8 {
	switch fam {
	case 1:
		return 4
	case 2:
		return 6
	}
	return 0
}

// slotIndex is the entry of rfm_iface_arr for slot, dir and fam
func slotIndex(slot int, dir uint8, fam int) uint32 {
	return uint32(slot*2*ifaceFamilies + int(dir)*ifaceFamilies + fam)
}

// slotAlloc hands out the counter slots of rfm_iface_arr, the lowest free one
// first, to the ifindexes rfm_iface_slot can index, an interface without a
// slot counts in the hash
type slotAlloc struct {
	maxIfindex uint32
	byIfindex  map[uint32]int
	used       []bool
}

func newSlotAlloc(slots int, maxIfindex uint32) *slotAlloc {
	return &slotAlloc{
		maxIfindex: maxIfindex,
		byIfindex:  make(map[uint32]int),
		used:       make([]bool, slots),
	}
}

// assign returns the slot of ifindex and gives it the lowest free one when it
// has none, fresh reports a slot that was free until now, ok is false when
// ifindex is out of range or no slot is free
func (a *slotAlloc) assign(ifindex uint32) (slot int, fresh, ok bool) {
	if s, held := a.byIfindex[ifindex]; held {
		return s, false, true
	}
	if ifindex >= a.maxIfindex {
		return 0, false, false
	}
	for s := range a.used {
		if !a.used[s] {
			a.used[s] = true
			a.byIfindex[ifindex] = s
			return s, true, true
		}
	}
	return 0, false, false
}

// restore records the slot an earlier run gave ifindex, read back from the
// pinned slot map, and refuses one out of range or already taken
func (a *slotAlloc) restore(ifindex uint32, slot int) bool {
	if ifindex >= a.maxIfindex || slot < 0 || slot >= len(a.used) || a.used[slot] {
		return false
	}
	if _, held := a.byIfindex[ifindex]; held {
		return false
	}
	a.used[slot] = true
	a.byIfindex[ifindex] = slot
	return true
}

// release frees the slot of ifindex and returns it
func (a *slotAlloc) release(ifindex uint32) (int, bool) {
	s, held := a.byIfindex[ifindex]
	if !held {
		return 0, false
	}
	delete(a.byIfindex, ifindex)
	a.used[s] = false
	return s, true
}

// held returns a copy of the slot of every slotted ifindex
func (a *slotAlloc) held() map[uint32]int {
	out := make(map[uint32]int, len(a.byIfindex))
	maps.Copy(out, a.byIfindex)
	return out
}
