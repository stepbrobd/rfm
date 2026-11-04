package collector

import "iter"

// flowRef names a slot of the flow table, 0 names none
type flowRef uint32

// flowLinks are the neighbors of a flow in one list of the table
type flowLinks struct {
	prev, next flowRef
}

// flowList is the oldest and the newest flow of one list of the table
type flowList struct {
	head, tail flowRef
}

// the lists of the flow table, a flow's links hold its place in each
const (
	// lruList orders the flows by their last event to within the lru slack, oldest first, it links the free slots too
	lruList = iota
	// activeList orders the flows by the start of their unexported interval, oldest first
	activeList
)

// tableChunkBits sets the slots of a chunk, 1024 slots of 256 bytes
const tableChunkBits = 10

const tableChunk = 1 << tableChunkBits

// flowTable holds the flows in chunks that never move and names each by its slot, so a flow costs no allocation once the table has grown and the map holds no pointers
type flowTable struct {
	index  map[flowID]flowRef
	chunks []*[tableChunk]flowState
	lists  [2]flowList
	// free heads the slots of removed flows, linked through their lru links
	free flowRef
	// next is the first slot never handed out, slot 0 stays unused so that 0 names none
	next flowRef
}

func newFlowTable() flowTable {
	return flowTable{index: make(map[flowID]flowRef), next: 1}
}

// at returns the flow in slot r
func (t *flowTable) at(r flowRef) *flowState {
	return &t.chunks[r>>tableChunkBits][r&(tableChunk-1)]
}

// len returns the number of flows
func (t *flowTable) len() int {
	return len(t.index)
}

// get returns the slot of the flow under id, which it takes by pointer so the map hashes the id in place and not a fresh copy
func (t *flowTable) get(id *flowID) (flowRef, bool) {
	r, ok := t.index[*id]
	return r, ok
}

// add stores s under id as the newest flow of both lists and returns its slot
func (t *flowTable) add(id flowID, s *flowState) flowRef {
	r := t.free
	if r != 0 {
		t.free = t.at(r).links[lruList].next
	} else {
		if int(t.next>>tableChunkBits) == len(t.chunks) {
			t.chunks = append(t.chunks, new([tableChunk]flowState))
		}
		r = t.next
		t.next++
	}
	*t.at(r) = *s
	t.index[id] = r
	t.pushBack(lruList, r)
	t.pushBack(activeList, r)
	return r
}

// remove takes the flow in slot r out of the table and clears the slot, so it keeps nothing of the flow alive
func (t *flowTable) remove(r flowRef) {
	s := t.at(r)
	t.unlink(lruList, r)
	t.unlink(activeList, r)
	delete(t.index, s.key.id())
	*s = flowState{}
	s.links[lruList].next = t.free
	t.free = r
}

// front returns the oldest flow of list l, 0 when the list is empty
func (t *flowTable) front(l int) flowRef {
	return t.lists[l].head
}

// moveToBack makes the flow in slot r the newest of list l
func (t *flowTable) moveToBack(l int, r flowRef) {
	if t.lists[l].tail == r {
		return
	}
	t.unlink(l, r)
	t.pushBack(l, r)
}

func (t *flowTable) pushBack(l int, r flowRef) {
	tail := t.lists[l].tail
	t.at(r).links[l] = flowLinks{prev: tail}
	if tail == 0 {
		t.lists[l].head = r
	} else {
		t.at(tail).links[l].next = r
	}
	t.lists[l].tail = r
}

func (t *flowTable) unlink(l int, r flowRef) {
	ln := t.at(r).links[l]
	if ln.prev == 0 {
		t.lists[l].head = ln.next
	} else {
		t.at(ln.prev).links[l].next = ln.next
	}
	if ln.next == 0 {
		t.lists[l].tail = ln.prev
	} else {
		t.at(ln.next).links[l].prev = ln.prev
	}
}

// all yields every flow, in no fixed order
func (t *flowTable) all() iter.Seq[*flowState] {
	return func(yield func(*flowState) bool) {
		for _, r := range t.index {
			if !yield(t.at(r)) {
				return
			}
		}
	}
}
