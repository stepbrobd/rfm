package collector

import (
	"reflect"
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

// tableFlow returns a flow whose key is the one of tableID(i), as the table removes a flow by its key
func tableFlow(i int) *flowState {
	id := tableID(i)
	return &flowState{key: id.key(), entry: FlowEntry{Packets: uint64(i + 1)}}
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
	a := tab.add(tableID(1), tableFlow(1))
	b := tab.add(tableID(2), tableFlow(2))
	c := tab.add(tableID(3), tableFlow(3))
	tab.remove(b)
	d := tab.add(tableID(4), tableFlow(4))

	if d != b {
		t.Fatalf("new flow took slot %d, want the freed slot %d", d, b)
	}
	if got, ok := tab.get(new(tableID(4))); !ok || got != d {
		t.Fatalf("get of the new flow = %d %v, want %d true", got, ok, d)
	}
	if _, ok := tab.get(new(tableID(2))); ok {
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
	a := tab.add(tableID(1), tableFlow(1))
	b := tab.add(tableID(2), tableFlow(2))
	c := tab.add(tableID(3), tableFlow(3))
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

func TestFlowTableKeepsNothingOfARemovedFlowAlive(t *testing.T) {
	tab := newFlowTable()
	f := tableFlow(1)
	f.rollup = 7
	f.entry.Src = Labels{City: "x"}
	r := tab.add(tableID(1), f)
	tab.remove(r)

	// a free slot holds only its link to the next free slot
	s := *tab.at(r)
	s.links = [2]flowLinks{}
	if s != (flowState{}) {
		t.Fatalf("removed flow left %+v in its slot", s)
	}
}

func TestFlowTableGrowsByChunksThatDoNotMove(t *testing.T) {
	tab := newFlowTable()
	first := tab.add(tableID(0), tableFlow(0))
	held := tab.at(first)
	for i := 1; i <= tableChunk; i++ {
		tab.add(tableID(i), tableFlow(i))
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
	// an index without pointers is one the garbage collector never scans
	if typ := reflect.TypeFor[map[flowID]flowRef](); hasPointers(typ.Key()) || hasPointers(typ.Elem()) {
		t.Fatal("the index of the flow table holds pointers")
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
