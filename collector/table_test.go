package collector

import (
	"reflect"
	"testing"
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
	f.rollup = &rollupState{}
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
