package collector

import (
	"maps"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"
	"unsafe"
)

// tableID returns a distinct flow id for each i
func tableID(i int) flowID {
	var id flowID
	id.addrs[0], id.addrs[1], id.addrs[2] = byte(i>>16), byte(i>>8), byte(i)
	return id
}

// tableFlow returns the flow of tableID(i) under hash h, the table finds a flow by both and lets go of it by its hash
func tableFlow(i int, h uint64) *flowState {
	return &flowState{id: tableID(i), hash: h, entry: FlowEntry{Packets: uint64(i + 1)}}
}

// order returns the slots of list l from the oldest to the newest
func order(t *flowTable, l int) []flowRef {
	var rs []flowRef
	for r := t.front(l); r != 0; r = t.at(r).links[l].next {
		rs = append(rs, r)
	}
	return rs
}

func TestFlowTableReusesTheSlotOfARemovedFlow(t *testing.T) {
	tab := newFlowTable()
	a := tab.add(tableFlow(1, 1))
	b := tab.add(tableFlow(2, 2))
	c := tab.add(tableFlow(3, 3))
	tab.remove(b)
	d := tab.add(tableFlow(4, 4))

	if d != b {
		t.Fatalf("new flow took slot %d, want the freed slot %d", d, b)
	}
	if got, ok := tab.get(4, new(tableID(4))); !ok || got != d {
		t.Fatalf("get of the new flow = %d %v, want %d true", got, ok, d)
	}
	if _, ok := tab.get(2, new(tableID(2))); ok {
		t.Fatal("the removed flow is still in the index")
	}
	for _, l := range []int{lruList, activeList} {
		if got, want := order(&tab, l), []flowRef{a, c, d}; !reflect.DeepEqual(got, want) {
			t.Fatalf("list %d is %v, want %v", l, got, want)
		}
	}
	if tab.len() != 3 {
		t.Fatalf("len = %d, want 3", tab.len())
	}
}

func TestFlowTableMovesAFlowToTheBackOfOneList(t *testing.T) {
	tab := newFlowTable()
	a := tab.add(tableFlow(1, 1))
	b := tab.add(tableFlow(2, 2))
	c := tab.add(tableFlow(3, 3))
	tab.moveToBack(lruList, a)
	tab.moveToBack(lruList, c)

	if got, want := order(&tab, lruList), []flowRef{b, a, c}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lru is %v, want %v", got, want)
	}
	if got, want := order(&tab, activeList), []flowRef{a, b, c}; !reflect.DeepEqual(got, want) {
		t.Fatalf("active list is %v, want %v", got, want)
	}
	tab.remove(c)
	tab.remove(b)
	tab.remove(a)
	if tab.front(lruList) != 0 || tab.front(activeList) != 0 || tab.len() != 0 {
		t.Fatalf("emptied table has fronts %d %d and len %d", tab.front(lruList), tab.front(activeList), tab.len())
	}
}

func TestFlowTableKeepsFlowsWhoseHashesCollideApart(t *testing.T) {
	// three flows under one hash take three cells, a lookup probes past the others by id
	tab := newFlowTable()
	a := tab.add(tableFlow(1, 7))
	b := tab.add(tableFlow(2, 7))
	c := tab.add(tableFlow(3, 7))
	if tab.len() != 3 {
		t.Fatalf("len %d, want 3", tab.len())
	}
	found := func(i int, want flowRef) {
		t.Helper()
		if got, ok := tab.get(7, new(tableID(i))); !ok || got != want {
			t.Fatalf("get of flow %d = %d %v, want %d true", i, got, ok, want)
		}
	}
	gone := func(i int) {
		t.Helper()
		if got, ok := tab.get(7, new(tableID(i))); ok {
			t.Fatalf("get of flow %d = %d, want it absent", i, got)
		}
	}
	found(1, a)
	found(2, b)
	found(3, c)
	gone(4)

	// the first flow under the hash leaves, the others stay found and a new one joins them
	tab.remove(a)
	gone(1)
	found(2, b)
	found(3, c)
	d := tab.add(tableFlow(4, 7))
	found(4, d)

	// a flow in the middle of the run leaves by its slot
	tab.remove(c)
	gone(3)
	found(2, b)
	found(4, d)
	var all []flowRef
	for r := range tab.all() {
		all = append(all, r)
	}
	slices.Sort(all)
	if want := []flowRef{min(b, d), max(b, d)}; !reflect.DeepEqual(all, want) {
		t.Fatalf("all yields %v, want %v", all, want)
	}
	tab.remove(b)
	tab.remove(d)
	if tab.len() != 0 {
		t.Fatalf("emptied table has len %d", tab.len())
	}
	for _, cell := range tab.index.cells {
		if cell.ref != 0 {
			t.Fatalf("emptied table still names slot %d", cell.ref)
		}
	}
}

func TestFlowIndexMatchesAMapUnderRandomUse(t *testing.T) {
	// a few tags in a small space make long runs that wrap past the last cell, so every move of a delete runs
	for seed := range uint64(60) {
		rng := rand.New(rand.NewPCG(seed, 1))
		tags := 1 + rng.IntN(64)
		var x flowIndex
		want := map[flowRef]uint32{}
		next := flowRef(1)
		for step := range 1000 {
			if len(want) > 0 && rng.IntN(5) < 2 {
				// delete a named slot
				keys := slices.Sorted(maps.Keys(want))
				r := keys[rng.IntN(len(keys))]
				x.del(want[r], r)
				delete(want, r)
			} else {
				// a tag near the top of the space homes on the last cells, so its run wraps
				tag := uint32(rng.IntN(tags)) << 26
				if rng.IntN(2) == 0 {
					tag = ^uint32(0) - uint32(rng.IntN(tags))
				}
				x.put(tag, next)
				want[next] = tag
				next++
			}
			if x.n != len(want) {
				t.Fatalf("seed %d step %d: index holds %d, want %d", seed, step, x.n, len(want))
			}
			// every named slot is found from its home before an empty cell
			for r, tag := range want {
				mask := len(x.cells) - 1
				i := x.home(tag)
				for x.cells[i].ref != r {
					if x.cells[i].ref == 0 {
						t.Fatalf("seed %d step %d: slot %d under tag %#x is not found from its home", seed, step, r, tag)
					}
					i = (i + 1) & mask
				}
			}
			seen := 0
			for _, c := range x.cells {
				if c.ref != 0 {
					if want[c.ref] != c.tag {
						t.Fatalf("seed %d step %d: cell names slot %d under tag %#x, want %#x", seed, step, c.ref, c.tag, want[c.ref])
					}
					seen++
				}
			}
			if seen != len(want) {
				t.Fatalf("seed %d step %d: %d cells are taken, want %d", seed, step, seen, len(want))
			}
		}
	}
}

func TestFlowTableKeepsNothingOfARemovedFlowAlive(t *testing.T) {
	tab := newFlowTable()
	f := tableFlow(1, 1)
	f.rollup = 7
	f.entry.Src = Labels{City: "x"}
	r := tab.add(f)
	tab.keepKey(r, FlowKey{SrcAddr: netip.MustParseAddr("192.0.2.1")})
	tab.remove(r)

	// a free slot holds only its link to the next free slot
	s := *tab.at(r)
	s.links = [2]flowLinks{}
	if s != (flowState{}) {
		t.Fatalf("removed flow left %+v in its slot", s)
	}
	if len(tab.keys) != 0 {
		t.Fatalf("removed flow left its key %+v", tab.keys)
	}
}

func TestFlowTableGrowsByChunksThatDoNotMove(t *testing.T) {
	tab := newFlowTable()
	first := tab.add(tableFlow(0, 0))
	held := tab.at(first)
	for i := 1; i <= tableChunk; i++ {
		tab.add(tableFlow(i, uint64(i)))
	}

	if len(tab.chunks) != 2 {
		t.Fatalf("table of %d flows has %d chunks, want 2", tab.len(), len(tab.chunks))
	}
	if tab.at(first) != held || held.entry.Packets != 1 {
		t.Fatal("a flow moved when the table grew")
	}
	got := order(&tab, lruList)
	if len(got) != tableChunk+1 {
		t.Fatalf("lru holds %d flows, want %d", len(got), tableChunk+1)
	}
	for i, r := range got {
		if p := tab.at(r).entry.Packets; p != uint64(i+1) {
			t.Fatalf("flow %d of the lru has %d packets, want %d", i, p, i+1)
		}
	}
}

func TestFlowTableSlotsAreLineAlignedAndItsIndexPointerFree(t *testing.T) {
	// a slot of four cache lines starts every flow of a chunk on a line
	if size := unsafe.Sizeof(flowState{}); size != 256 {
		t.Fatalf("flowState is %d bytes, want 256", size)
	}
	// a hit compares the id and updates the counters, all on the first two
	// lines, so the compare costs no line of its own
	if off := unsafe.Offsetof(flowState{}.id); off != 0 {
		t.Fatalf("the id starts at byte %d of the slot, want it first", off)
	}
	if end := unsafe.Offsetof(flowState{}.entry) + unsafe.Offsetof(FlowEntry{}.LastSeen) + unsafe.Sizeof(time.Duration(0)); end > 128 {
		t.Fatalf("the fields a hit touches end at byte %d, past the first two lines", end)
	}
	// an index without pointers is one the garbage collector never scans
	if hasPointers(reflect.TypeFor[indexCell]()) {
		t.Fatal("the index of the flow table holds pointers")
	}
	if size := unsafe.Sizeof(indexCell{}); size != 8 {
		t.Fatalf("an index cell is %d bytes, want 8", size)
	}
}

// rollupKey returns a distinct tuple key for each i
func rollupKey(i int) RollupKey {
	return RollupKey{Ifindex: 1, Proto: 6, Src: Labels{ASN: uint32(i), City: "x"}}
}

// idleOrder returns the idle tuples from the one idle the longest on
func idleOrder(t *rollupTable) []rollupRef {
	var rs []rollupRef
	for r := t.front(); r != 0; r = t.at(r).links.next {
		rs = append(rs, r)
	}
	return rs
}

func TestRollupTableListsIdleTuplesInTheOrderTheyWentIdle(t *testing.T) {
	tab := newRollupTable()
	a := tab.add(rollupKey(1))
	b := tab.add(rollupKey(2))
	c := tab.add(rollupKey(3))
	// a new tuple waits in the idle list for its first flow
	if got, want := idleOrder(&tab), []rollupRef{a, b, c}; !reflect.DeepEqual(got, want) {
		t.Fatalf("idle list of new tuples is %v, want %v", got, want)
	}
	tab.unlink(b)
	tab.unlink(a)
	tab.unlink(c)
	if tab.front() != 0 {
		t.Fatalf("idle list holds %v once every tuple has a flow", idleOrder(&tab))
	}
	tab.pushBack(c)
	tab.pushBack(a)
	tab.pushBack(b)
	tab.unlink(a)
	if got, want := idleOrder(&tab), []rollupRef{c, b}; !reflect.DeepEqual(got, want) {
		t.Fatalf("idle list is %v, want %v", got, want)
	}
}

func TestRollupTableReusesTheSlotOfADroppedTuple(t *testing.T) {
	tab := newRollupTable()
	a := tab.add(rollupKey(1))
	b := tab.add(rollupKey(2))
	tab.drop(a)
	c := tab.add(rollupKey(3))

	if c != a {
		t.Fatalf("new tuple took slot %d, want the freed slot %d", c, a)
	}
	if _, ok := tab.get(rollupKey(1)); ok {
		t.Fatal("the dropped tuple is still in the index")
	}
	if got, ok := tab.get(rollupKey(3)); !ok || got != c {
		t.Fatalf("get of the new tuple = %d %v, want %d true", got, ok, c)
	}
	// the slot holds a new life of a tuple, with an id of its own
	if s := tab.at(c); s.key != rollupKey(3) || s.id != 3 || s.Counts != (Counts{}) {
		t.Fatalf("reused slot holds %+v, want a fresh tuple under the new key with id 3", *s)
	}
	if got, want := idleOrder(&tab), []rollupRef{b, c}; !reflect.DeepEqual(got, want) {
		t.Fatalf("idle list is %v, want %v", got, want)
	}
	if tab.len() != 2 {
		t.Fatalf("len = %d, want 2", tab.len())
	}
}

func TestRollupTableKeepsNothingOfADroppedTupleAlive(t *testing.T) {
	tab := newRollupTable()
	r := tab.add(rollupKey(1))
	tab.at(r).add(Counts{Packets: 1}, time.Second)
	tab.drop(r)

	// a free slot holds only its link to the next free slot
	s := *tab.at(r)
	s.links = rollupLinks{}
	if s != (rollupState{}) {
		t.Fatalf("dropped tuple left %+v in its slot", s)
	}
}

func TestRollupTableSlotsAreLineAlignedAndItsIndexValuesPointerFree(t *testing.T) {
	// a slot of two cache lines starts every tuple of a chunk on a line, and
	// the fields an event touches fit in the first
	if size := unsafe.Sizeof(rollupState{}); size != 128 {
		t.Fatalf("rollupState is %d bytes, want 128", size)
	}
	if end := unsafe.Offsetof(rollupState{}.shown) + 1; end > 64 {
		t.Fatalf("the fields an event touches end at byte %d, past the first line", end)
	}
	// the labels of the key hold strings, the slots the index names do not
	if hasPointers(reflect.TypeFor[map[RollupKey]rollupRef]().Elem()) {
		t.Fatal("the index of the rollup table holds pointers in its values")
	}
}
