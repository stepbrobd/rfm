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

// tableChunkBits sets the slots of a chunk, 1024 slots of 256 bytes for flows and of 128 for tuples
const tableChunkBits = 10

const tableChunk = 1 << tableChunkBits

// flowTable holds the flows in chunks that never move and names each by its slot, so a flow costs no allocation once the table has grown and its index holds no pointers
type flowTable struct {
	// index names each flow under the table hash of its id, but for a flow whose hash it already gives to another
	index map[uint64]flowRef
	// overflow names by id the flows whose hash the index gave to another flow, which takes a collision of 64 bit hashes
	overflow map[flowID]flowRef
	// keys holds the key of a flow whose event named an address in a form its id does not keep, 4 byte, zoned or invalid, events from the rings never do
	keys   map[flowRef]FlowKey
	chunks []*[tableChunk]flowState
	lists  [2]flowList
	// free heads the slots of removed flows, linked through their lru links
	free flowRef
	// next is the first slot never handed out, slot 0 stays unused so that 0 names none
	next flowRef
}

func newFlowTable() flowTable {
	return flowTable{index: make(map[uint64]flowRef), overflow: make(map[flowID]flowRef), keys: make(map[flowRef]FlowKey), next: 1}
}

// at returns the flow in slot r
func (t *flowTable) at(r flowRef) *flowState {
	return &t.chunks[r>>tableChunkBits][r&(tableChunk-1)]
}

// len returns the number of flows
func (t *flowTable) len() int {
	return len(t.index) + len(t.overflow)
}

// get returns the slot of the flow under id, whose hash is h, the id it compares sits on the lines a hit goes on to update
func (t *flowTable) get(h uint64, id *flowID) (flowRef, bool) {
	if r, ok := t.index[h]; ok && t.at(r).id.equal(id) {
		return r, true
	}
	if len(t.overflow) == 0 {
		return 0, false
	}
	r, ok := t.overflow[*id]
	return r, ok
}

// add stores s, which carries its id and its hash, as the newest flow of both lists and returns its slot
func (t *flowTable) add(s *flowState) flowRef {
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
	if _, taken := t.index[s.hash]; taken {
		t.overflow[s.id] = r
	} else {
		t.index[s.hash] = r
	}
	t.pushBack(lruList, r)
	t.pushBack(activeList, r)
	return r
}

// keepKey makes key the one a listing shows for the flow in slot r, it names the flow's id in a form the id does not keep
func (t *flowTable) keepKey(r flowRef, key FlowKey) {
	t.keys[r] = key
}

// key returns the key of the flow in slot r as its event named it
func (t *flowTable) key(r flowRef) FlowKey {
	if len(t.keys) != 0 {
		if k, ok := t.keys[r]; ok {
			return k
		}
	}
	return t.at(r).id.key()
}

// remove takes the flow in slot r out of the table and clears the slot, so it keeps nothing of the flow alive
func (t *flowTable) remove(r flowRef) {
	s := t.at(r)
	t.unlink(lruList, r)
	t.unlink(activeList, r)
	// the index names the flow under its hash unless the flow is in overflow
	if len(t.overflow) != 0 && t.index[s.hash] != r {
		delete(t.overflow, s.id)
	} else {
		delete(t.index, s.hash)
	}
	if len(t.keys) != 0 {
		delete(t.keys, r)
	}
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

// all yields every flow with its slot, in no fixed order
func (t *flowTable) all() iter.Seq2[flowRef, *flowState] {
	return func(yield func(flowRef, *flowState) bool) {
		for _, r := range t.index {
			if !yield(r, t.at(r)) {
				return
			}
		}
		for _, r := range t.overflow {
			if !yield(r, t.at(r)) {
				return
			}
		}
	}
}

// rollupRef names a slot of the rollup table, 0 names none
type rollupRef uint32

// rollupLinks are the neighbors of a tuple in the idle list of the rollup table
type rollupLinks struct {
	prev, next rollupRef
}

// rollupTable holds the label tuples in chunks that never move and names each by its slot, so a new tuple costs no allocation once the table has grown and a tuple going idle costs none
type rollupTable struct {
	index  map[RollupKey]rollupRef
	chunks []*[tableChunk]rollupState
	// idle lists every tuple without live flows by when it lost its last one, oldest first, a new tuple waits there for its first flow
	idle struct{ head, tail rollupRef }
	// free heads the slots of dropped tuples, linked through their next links
	free rollupRef
	// next is the first slot never handed out, slot 0 stays unused so that 0 names none
	next rollupRef
	// ids counts the tuples ever made, the newest has the count as its id
	ids uint64
}

func newRollupTable() rollupTable {
	return rollupTable{index: make(map[RollupKey]rollupRef), next: 1}
}

// at returns the tuple in slot r
func (t *rollupTable) at(r rollupRef) *rollupState {
	return &t.chunks[r>>tableChunkBits][r&(tableChunk-1)]
}

// len returns the number of tuples
func (t *rollupTable) len() int {
	return len(t.index)
}

// get returns the slot of the tuple under k
func (t *rollupTable) get(k RollupKey) (rollupRef, bool) {
	r, ok := t.index[k]
	return r, ok
}

// add stores a new tuple under k as the newest idle tuple and returns its slot
func (t *rollupTable) add(k RollupKey) rollupRef {
	r := t.free
	if r != 0 {
		t.free = t.at(r).links.next
	} else {
		if int(t.next>>tableChunkBits) == len(t.chunks) {
			t.chunks = append(t.chunks, new([tableChunk]rollupState))
		}
		r = t.next
		t.next++
	}
	t.ids++
	*t.at(r) = rollupState{key: k, id: t.ids}
	t.index[k] = r
	t.pushBack(r)
	return r
}

// drop takes the idle tuple in slot r out of the table and clears the slot, so it keeps nothing of the tuple alive
func (t *rollupTable) drop(r rollupRef) {
	s := t.at(r)
	t.unlink(r)
	delete(t.index, s.key)
	*s = rollupState{}
	s.links.next = t.free
	t.free = r
}

// front returns the tuple idle the longest, 0 when none is idle
func (t *rollupTable) front() rollupRef {
	return t.idle.head
}

// pushBack makes the tuple in slot r the newest idle tuple
func (t *rollupTable) pushBack(r rollupRef) {
	tail := t.idle.tail
	t.at(r).links = rollupLinks{prev: tail}
	if tail == 0 {
		t.idle.head = r
	} else {
		t.at(tail).links.next = r
	}
	t.idle.tail = r
}

// unlink takes the tuple in slot r out of the idle list
func (t *rollupTable) unlink(r rollupRef) {
	ln := t.at(r).links
	if ln.prev == 0 {
		t.idle.head = ln.next
	} else {
		t.at(ln.prev).links.next = ln.next
	}
	if ln.next == 0 {
		t.idle.tail = ln.prev
	} else {
		t.at(ln.next).links.prev = ln.prev
	}
}

// all yields every tuple, in no fixed order
func (t *rollupTable) all() iter.Seq[*rollupState] {
	return func(yield func(*rollupState) bool) {
		for _, r := range t.index {
			if !yield(t.at(r)) {
				return
			}
		}
	}
}
