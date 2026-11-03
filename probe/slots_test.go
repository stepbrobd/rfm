package probe

import "testing"

func TestSlotAllocAssignsLowestFree(t *testing.T) {
	a := newSlotAlloc(3, 100)
	for i, ifindex := range []uint32{7, 3, 9} {
		s, fresh, ok := a.assign(ifindex)
		if !ok || !fresh || s != i {
			t.Fatalf("assign(%d) = %d %v %v, want slot %d fresh", ifindex, s, fresh, ok, i)
		}
	}
	// a held slot comes back as it is, not fresh
	if s, fresh, ok := a.assign(3); !ok || fresh || s != 1 {
		t.Fatalf("assign(3) again = %d %v %v, want slot 1 held", s, fresh, ok)
	}
	// every slot taken, the next interface counts in the hash
	if _, _, ok := a.assign(11); ok {
		t.Fatal("assign with every slot taken succeeded")
	}
	// a released slot is reused first, and fresh again
	if s, ok := a.release(3); !ok || s != 1 {
		t.Fatalf("release(3) = %d %v, want slot 1", s, ok)
	}
	if _, ok := a.release(3); ok {
		t.Fatal("second release(3) succeeded")
	}
	if s, fresh, ok := a.assign(11); !ok || !fresh || s != 1 {
		t.Fatalf("assign(11) = %d %v %v, want the freed slot 1 fresh", s, fresh, ok)
	}
}

func TestSlotAllocRefusesIfindexOutOfRange(t *testing.T) {
	a := newSlotAlloc(4, 100)
	if _, _, ok := a.assign(100); ok {
		t.Fatal("assign of an ifindex the slot map cannot index succeeded")
	}
	if a.restore(100, 0) {
		t.Fatal("restore of an ifindex the slot map cannot index succeeded")
	}
}

func TestSlotAllocRestore(t *testing.T) {
	a := newSlotAlloc(4, 100)
	if !a.restore(5, 2) {
		t.Fatal("restore(5, 2) failed")
	}
	// a restored slot is held, not fresh, and never handed to another
	if s, fresh, ok := a.assign(5); !ok || fresh || s != 2 {
		t.Fatalf("assign(5) after restore = %d %v %v, want slot 2 held", s, fresh, ok)
	}
	if a.restore(6, 2) {
		t.Fatal("restore of a taken slot succeeded")
	}
	if a.restore(5, 3) {
		t.Fatal("second restore of a slotted ifindex succeeded")
	}
	if a.restore(7, 4) {
		t.Fatal("restore of a slot past the array succeeded")
	}
	for i, ifindex := range []uint32{8, 9, 10} {
		want := []int{0, 1, 3}[i]
		if s, _, ok := a.assign(ifindex); !ok || s != want {
			t.Fatalf("assign(%d) = %d %v, want slot %d", ifindex, s, ok, want)
		}
	}
}

func TestSlotIndexLayout(t *testing.T) {
	// slot * 2 * RFM_FAMILIES + dir * RFM_FAMILIES + family, as in rfm_tc.c
	if got := slotIndex(0, 0, 0); got != 0 {
		t.Fatalf("slotIndex(0, 0, 0) = %d", got)
	}
	if got := slotIndex(2, 1, 2); got != 2*6+3+2 {
		t.Fatalf("slotIndex(2, 1, 2) = %d", got)
	}
	for fam, proto := range []uint8{0, 4, 6} {
		if got := familyProto(fam); got != proto {
			t.Fatalf("familyProto(%d) = %d, want %d", fam, got, proto)
		}
	}
}
